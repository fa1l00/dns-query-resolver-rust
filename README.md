# DNS Query Resolver (Rust)

Навчальна консольна утиліта для надсилання DNS-запитів типів **A** та **AAAA** до вказаного DNS-сервера через UDP.

## Можливості

- формує DNS-повідомлення згідно з RFC 1035;
- надсилає запити UDP на порт 53;
- розбирає A (IPv4) та AAAA (IPv6) записи;
- перевіряє ідентифікатор і прапорці відповіді;
- обробляє NXDOMAIN, SERVFAIL, REFUSED, тайм-аут і некоректні пакети;
- підтримує compression pointers у DNS-іменах;
- не має сторонніх залежностей.

## Вимоги

- Rust toolchain (rustc і Cargo), edition 2021;
- доступ до мережі та доступний DNS-сервер.

## Збирання та перевірка

```bash
cargo build --release
cargo test
```

## Приклади запуску

```bash
# Отримати IPv4 та IPv6 адреси
cargo run -- example.com

# Лише IPv4
cargo run -- example.com --type A

# Лише IPv6
cargo run -- example.com --type AAAA

# Вказати DNS-сервер та тайм-аут
cargo run -- example.com --type ALL --server 8.8.8.8:53 --timeout-ms 5000
```

За замовчуванням використовується DNS-сервер `1.1.1.1:53`, тип запиту `ALL` та тайм-аут 3000 мс. Для параметра `--server` потрібно вказати числову IP-адресу з портом.

## Обмеження навчальної версії

Програма виконує прямий запит до одного рекурсивного DNS-сервера, не реалізує власну рекурсію, кешування, DNSSEC, DoT/DoH або повторне надсилання. Якщо встановлено прапорець TC (truncated), програма повідомляє про обрізану відповідь; перехід на TCP не реалізований. Доменні мітки приймаються в ASCII; для міжнародних доменів потрібно заздалегідь використовувати IDNA/Punycode-представлення.

## Структура проєкту

```text
.
├── Cargo.toml
├── README.md
├── LICENSE
├── .gitignore
├── .github/workflows/ci.yml
└── src/main.rs
```

## Публікація на GitHub

Створіть порожній репозиторій `dns-query-resolver-rust` у своєму GitHub-акаунті, розпакуйте архів і виконайте:

```bash
git init
git add .
git commit -m "Initial DNS Query Resolver implementation"
git branch -M main
git remote add origin https://github.com/<YOUR-USERNAME>/dns-query-resolver-rust.git
git push -u origin main
```

Після публікації замініть `<YOUR-USERNAME>` на власний логін GitHub і вставте реальне посилання до розділу «Доступність даних» курсової роботи.
