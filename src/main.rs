use std::env;
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DNS_PORT: u16 = 53;
const DNS_HEADER_LEN: usize = 12;
const DNS_BUFFER_SIZE: usize = 4096;
const CLASS_IN: u16 = 1;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;

#[derive(Debug, Clone, Copy)]
enum QueryType {
    A,
    Aaaa,
    All,
}

impl QueryType {
    fn from_str(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "a" => Ok(Self::A),
            "aaaa" => Ok(Self::Aaaa),
            "all" => Ok(Self::All),
            _ => Err(format!("Непідтримуваний тип запису: {value}. Використайте A, AAAA або ALL.")),
        }
    }

    fn codes(self) -> &'static [u16] {
        match self {
            Self::A => &[TYPE_A],
            Self::Aaaa => &[TYPE_AAAA],
            Self::All => &[TYPE_A, TYPE_AAAA],
        }
    }
}

#[derive(Debug)]
struct DnsError(String);

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for DnsError {}

fn next_query_id() -> u16 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    (nanos as u16) ^ ((nanos >> 32) as u16)
}

fn encode_domain_name(domain: &str) -> Result<Vec<u8>, DnsError> {
    let normalized = domain.trim().trim_end_matches('.');
    if normalized.is_empty() {
        return Err(DnsError("Доменне ім'я не може бути порожнім".into()));
    }

    let mut encoded = Vec::with_capacity(normalized.len() + 2);
    for label in normalized.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DnsError(format!("Некоректна довжина мітки домену: '{label}'")));
        }
        if !label.is_ascii()
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(DnsError(format!("Некоректна мітка домену: '{label}'")));
        }
        encoded.push(label.len() as u8);
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0);

    if encoded.len() > 255 {
        return Err(DnsError("Доменне ім'я перевищує 255 октетів".into()));
    }
    Ok(encoded)
}

fn build_query(domain: &str, query_type: u16, id: u16) -> Result<Vec<u8>, DnsError> {
    if query_type != TYPE_A && query_type != TYPE_AAAA {
        return Err(DnsError("Для цієї програми дозволено лише типи A та AAAA".into()));
    }

    let mut packet = Vec::with_capacity(64);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100_u16.to_be_bytes()); // RD: recursion desired
    packet.extend_from_slice(&1_u16.to_be_bytes()); // QDCOUNT
    packet.extend_from_slice(&0_u16.to_be_bytes()); // ANCOUNT
    packet.extend_from_slice(&0_u16.to_be_bytes()); // NSCOUNT
    packet.extend_from_slice(&0_u16.to_be_bytes()); // ARCOUNT
    packet.extend_from_slice(&encode_domain_name(domain)?);
    packet.extend_from_slice(&query_type.to_be_bytes());
    packet.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(packet)
}

// Advances over an encoded DNS name and safely handles RFC 1035 compression pointers.
fn skip_name(packet: &[u8], offset: &mut usize) -> Result<(), DnsError> {
    let mut position = *offset;
    let mut jumped = false;
    let mut visited = Vec::new();
    let mut steps = 0usize;

    loop {
        if position >= packet.len() {
            return Err(DnsError("Неочікуваний кінець DNS-пакета під час читання імені".into()));
        }
        steps += 1;
        if steps > packet.len() {
            return Err(DnsError("Виявлено циклічне посилання у DNS-імені".into()));
        }
        let length = packet[position];

        if length & 0xC0 == 0xC0 {
            if position + 1 >= packet.len() {
                return Err(DnsError("Обрізаний compression pointer у DNS-пакеті".into()));
            }
            let pointer = (((length as usize) & 0x3F) << 8) | packet[position + 1] as usize;
            if pointer >= packet.len() || visited.contains(&pointer) {
                return Err(DnsError("Некоректний або циклічний compression pointer".into()));
            }
            visited.push(pointer);
            if !jumped {
                *offset = position + 2;
            }
            position = pointer;
            jumped = true;
        } else if length & 0xC0 != 0 {
            return Err(DnsError("Зарезервований формат мітки DNS-імені".into()));
        } else if length == 0 {
            if !jumped {
                *offset = position + 1;
            }
            return Ok(());
        } else {
            let end = position + 1 + length as usize;
            if end > packet.len() {
                return Err(DnsError("Мітка DNS-імені виходить за межі пакета".into()));
            }
            position = end;
        }
    }
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, DnsError> {
    let bytes = packet
        .get(offset..offset + 2)
        .ok_or_else(|| DnsError("Обрізане 16-бітове поле DNS-пакета".into()))?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn parse_response(packet: &[u8], expected_id: u16, expected_type: u16) -> Result<Vec<IpAddr>, DnsError> {
    if packet.len() < DNS_HEADER_LEN {
        return Err(DnsError("DNS-відповідь коротша за заголовок".into()));
    }
    let response_id = read_u16(packet, 0)?;
    if response_id != expected_id {
        return Err(DnsError("Ідентифікатор DNS-відповіді не збігається із запитом".into()));
    }

    let flags = read_u16(packet, 2)?;
    if flags & 0x8000 == 0 {
        return Err(DnsError("Отриманий пакет не є DNS-відповіддю".into()));
    }
    if flags & 0x0200 != 0 {
        return Err(DnsError("DNS-відповідь позначена як обрізана (TC=1); TCP fallback не реалізовано".into()));
    }
    let rcode = flags & 0x000F;
    match rcode {
        0 => {}
        3 => return Err(DnsError("Домен не знайдено (NXDOMAIN)".into())),
        2 => return Err(DnsError("DNS-сервер повідомив про внутрішню помилку (SERVFAIL)".into())),
        5 => return Err(DnsError("DNS-сервер відмовив у виконанні запиту (REFUSED)".into())),
        value => return Err(DnsError(format!("DNS-сервер повернув код помилки RCODE={value}"))),
    }

    let question_count = read_u16(packet, 4)? as usize;
    let answer_count = read_u16(packet, 6)? as usize;
    let mut offset = DNS_HEADER_LEN;

    for _ in 0..question_count {
        skip_name(packet, &mut offset)?;
        offset = offset
            .checked_add(4)
            .filter(|end| *end <= packet.len())
            .ok_or_else(|| DnsError("Обрізана секція запитання DNS-відповіді".into()))?;
    }

    let mut addresses = Vec::new();
    for _ in 0..answer_count {
        skip_name(packet, &mut offset)?;
        let rr_type = read_u16(packet, offset)?;
        let rr_class = read_u16(packet, offset + 2)?;
        let data_len = read_u16(packet, offset + 8)? as usize;
        let data_start = offset
            .checked_add(10)
            .ok_or_else(|| DnsError("Переповнення позиції DNS-пакета".into()))?;
        let data_end = data_start
            .checked_add(data_len)
            .filter(|end| *end <= packet.len())
            .ok_or_else(|| DnsError("RDATA виходить за межі DNS-пакета".into()))?;
        let data = &packet[data_start..data_end];

        if rr_class == CLASS_IN && rr_type == expected_type {
            match (rr_type, data.len()) {
                (TYPE_A, 4) => addresses.push(IpAddr::V4(Ipv4Addr::new(
                    data[0], data[1], data[2], data[3],
                ))),
                (TYPE_AAAA, 16) => {
                    let octets: [u8; 16] = data
                        .try_into()
                        .map_err(|_| DnsError("Некоректна довжина AAAA-запису".into()))?;
                    addresses.push(IpAddr::V6(Ipv6Addr::from(octets)));
                }
                _ => return Err(DnsError("Некоректна довжина адресного DNS-запису".into())),
            }
        }
        offset = data_end;
    }
    Ok(addresses)
}

fn resolve(domain: &str, query_type: u16, server: SocketAddr, timeout: Duration) -> Result<Vec<IpAddr>, DnsError> {
    let id = next_query_id();
    let query = build_query(domain, query_type, id)?;
    let bind_address = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = UdpSocket::bind(bind_address)
        .map_err(|e| DnsError(format!("Не вдалося відкрити UDP-сокет: {e}")))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|e| DnsError(format!("Не вдалося встановити тайм-аут: {e}")))?;
    socket
        .connect(server)
        .map_err(|e| DnsError(format!("Не вдалося під'єднати UDP-сокет до {server}: {e}")))?;
    socket
        .send(&query)
        .map_err(|e| DnsError(format!("Помилка надсилання DNS-запиту: {e}")))?;

    let mut buffer = [0_u8; DNS_BUFFER_SIZE];
    let received = socket
        .recv(&mut buffer)
        .map_err(|e| DnsError(format!("Не отримано DNS-відповідь від {server}: {e}")))?;
    parse_response(&buffer[..received], id, query_type)
}

fn print_help(program: &str) {
    println!("DNS Query Resolver - пошук IPv4 та IPv6 адрес за DNS");
    println!("\nВикористання: {program} <домен> [параметри]");
    println!("\nПараметри:");
    println!("  --type A|AAAA|ALL       Тип запиту (за замовчуванням ALL)");
    println!("  --server IP:PORT        DNS-сервер (за замовчуванням 1.1.1.1:53)");
    println!("  --timeout-ms N          Тайм-аут очікування у мілісекундах (за замовчуванням 3000)");
    println!("  -h, --help              Показати цю довідку");
}

fn run() -> Result<(), DnsError> {
    let args: Vec<String> = env::args().collect();
    let program = args.first().map(String::as_str).unwrap_or("dns-query-resolver");
    if args.len() == 1 || args.iter().any(|arg| arg == "-h" || arg == "--help") {
        print_help(program);
        return Ok(());
    }

    let domain = args.get(1).ok_or_else(|| DnsError("Не вказано домен".into()))?;
    let mut query_type = QueryType::All;
    let mut server = SocketAddr::from(([1, 1, 1, 1], DNS_PORT));
    let mut timeout_ms = 3000_u64;
    let mut index = 2;

    while index < args.len() {
        match args[index].as_str() {
            "--type" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| DnsError("Після --type потрібно вказати A, AAAA або ALL".into()))?;
                query_type = QueryType::from_str(value).map_err(DnsError)?;
            }
            "--server" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| DnsError("Після --server потрібно вказати IP:PORT".into()))?;
                server = SocketAddr::from_str(value)
                    .map_err(|_| DnsError("Адреса DNS-сервера має формат IP:PORT, наприклад 1.1.1.1:53".into()))?;
            }
            "--timeout-ms" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| DnsError("Після --timeout-ms потрібно вказати число".into()))?;
                timeout_ms = value.parse::<u64>().map_err(|_| DnsError("Тайм-аут має бути цілим невід'ємним числом".into()))?;
                if timeout_ms == 0 {
                    return Err(DnsError("Тайм-аут повинен бути більшим за нуль".into()));
                }
            }
            other => return Err(DnsError(format!("Невідомий параметр: {other}. Використайте --help"))),
        }
        index += 1;
    }

    println!("DNS Query Resolver");
    println!("Домен: {domain}");
    println!("DNS-сервер: {server}");
    println!("Тип запиту: {:?}", query_type);

    let mut any_found = false;
    for code in query_type.codes() {
        let label = if *code == TYPE_A { "A (IPv4)" } else { "AAAA (IPv6)" };
        println!("\n{label}:");
        match resolve(domain, *code, server, Duration::from_millis(timeout_ms)) {
            Ok(addresses) if addresses.is_empty() => println!("  Адресних записів цього типу не знайдено."),
            Ok(addresses) => {
                any_found = true;
                for address in addresses {
                    println!("  {address}");
                }
            }
            Err(error) => println!("  Помилка: {error}"),
        }
    }
    if !any_found {
        println!("\nНе отримано жодної IP-адреси.");
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Помилка: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_domain_name() {
        assert_eq!(encode_domain_name("example.com").unwrap(),
            vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]);
        assert_eq!(encode_domain_name("example.com.").unwrap(), encode_domain_name("example.com").unwrap());
    }

    #[test]
    fn rejects_invalid_domain_labels() {
        assert!(encode_domain_name("").is_err());
        assert!(encode_domain_name("-bad.example").is_err());
        assert!(encode_domain_name("bad..example").is_err());
        assert!(encode_domain_name("a_b.example").is_err());
        assert!(encode_domain_name(&format!("{}.com", "a".repeat(64))).is_err());
    }

    #[test]
    fn builds_a_query_header() {
        let packet = build_query("example.com", TYPE_A, 0x1234).unwrap();
        assert_eq!(read_u16(&packet, 0).unwrap(), 0x1234);
        assert_eq!(read_u16(&packet, 2).unwrap(), 0x0100);
        assert_eq!(read_u16(&packet, 4).unwrap(), 1);
        assert_eq!(read_u16(&packet, packet.len() - 4).unwrap(), TYPE_A);
        assert_eq!(read_u16(&packet, packet.len() - 2).unwrap(), CLASS_IN);
    }

    #[test]
    fn skips_compressed_name() {
        // A full DNS message starts with a 12-byte header; the pointer targets offset 12.
        let mut packet = vec![0_u8; DNS_HEADER_LEN];
        packet.extend_from_slice(&[3, b'w', b'w', b'w', 0]);
        packet.extend_from_slice(&[0xC0, 0x0C]);
        let mut offset = DNS_HEADER_LEN + 5;
        skip_name(&packet, &mut offset).unwrap();
        assert_eq!(offset, DNS_HEADER_LEN + 7);
    }

    #[test]
    fn parses_ipv4_answer() {
        let mut packet = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        packet.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]);
        packet.extend_from_slice(&TYPE_A.to_be_bytes());
        packet.extend_from_slice(&CLASS_IN.to_be_bytes());
        packet.extend_from_slice(&[0xC0, 0x0C]);
        packet.extend_from_slice(&TYPE_A.to_be_bytes());
        packet.extend_from_slice(&CLASS_IN.to_be_bytes());
        packet.extend_from_slice(&300_u32.to_be_bytes());
        packet.extend_from_slice(&4_u16.to_be_bytes());
        packet.extend_from_slice(&[93, 184, 216, 34]);
        let result = parse_response(&packet, 0x1234, TYPE_A).unwrap();
        assert_eq!(result, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
    }
}
