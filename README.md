<p align="right"><b>Русский</b> · <a href="README.en.md">English</a></p>

# ovpn-sender

Раздача готовых `.ovpn` профилей с эмуляцией импорта OpenVPN Access Server. Пользователь вводит в OpenVPN Connect (Import Profile -> URL) адрес сервера, логин и одноразовый пароль и получает профиль. Работает на iPhone, Android, Windows и macOS, ставить Access Server не нужно.

- один файл на Python, только стандартная библиотека;
- образ на `python:3.12-alpine`, около 50-60 МБ;
- одноразовые пароли со сроком жизни и лимитом импортов, защита от перебора;
- HTTPS прямо в контейнере на готовых PEM-сертификатах или работа за своим reverse proxy.

Валидный сертификат нужен в любом режиме: OpenVPN Connect ходит только по HTTPS и не принимает самоподписанные сертификаты.

## Содержание

- [Быстрый старт: HTTPS в контейнере](#быстрый-старт-https-в-контейнере)
- [За своим reverse proxy](#за-своим-reverse-proxy)
- [Профили и выдача доступа](#профили-и-выдача-доступа)
- [Переменные окружения](#переменные-окружения)
- [Самостоятельная сборка](#самостоятельная-сборка)
- [Публикация образа](#публикация-образа)
- [Протокол](#протокол)
- [Безопасность](#безопасность)

## Быстрый старт: HTTPS в контейнере

Нужен домен, указывающий на сервер (подойдёт DDNS), и сертификат на него. Если сертификата ещё нет, получите его на хосте. Порт 80 на это время должен быть свободен:

```bash
sudo certbot certonly --standalone -d vpn.example.com
```

Контейнер работает от uid 10001, а ключи Let's Encrypt по умолчанию читает только root. Выдайте права на чтение:

```bash
sudo setfacl -R -m u:10001:rX /etc/letsencrypt/live /etc/letsencrypt/archive
```

При продлении certbot создаёт новые файлы с правами 600, поэтому права нужно выдавать заново. Это делает deploy-хук:

```bash
printf '#!/bin/sh\nsetfacl -R -m u:10001:rX /etc/letsencrypt/live /etc/letsencrypt/archive\n' | sudo tee /etc/letsencrypt/renewal-hooks/deploy/ovpn-sender && sudo chmod 755 /etc/letsencrypt/renewal-hooks/deploy/ovpn-sender
```

Запуск:

```bash
docker pull mikedigriz/ovpn-sender:latest
```

```bash
docker run -d --name ovpn --restart unless-stopped \
  -p 443:8080 \
  -e OVPN_DOMAIN=vpn.example.com \
  -v /etc/letsencrypt:/etc/letsencrypt:ro \
  -v ovpn-data:/data \
  -v /srv/ovpn/profiles:/profiles:ro \
  mikedigriz/ovpn-sender:latest
```

`OVPN_DOMAIN` берёт сертификат из `/etc/letsencrypt/live/<домен>/`. Каталог монтируется целиком, потому что файлы в `live/` - симлинки на `archive/`. Продлённый сертификат контейнер подхватывает сам в течение часа, без перезапуска.

Сертификат не от certbot: смонтируйте любые PEM-файлы и задайте пути явно:

```bash
-v /path/to/certs:/certs:ro -e OVPN_CERT=/certs/fullchain.pem -e OVPN_KEY=/certs/privkey.pem
```

## За своим reverse proxy

Без сертификатов контейнер отдаёт HTTP на порту 8080, а наружу его публикует прокси.

```bash
git clone https://github.com/mikedigriz/ovpn-sender.git && cd ovpn-sender
cp .env.example .env    # OVPN_BASE_URL, OVPN_HOST_PORT, при желании OVPN_IMAGE
docker compose up -d
```

На прокси нужны три пути. Пример для Nginx - в [nginx/ovpn-sender.conf](nginx/ovpn-sender.conf).

| Путь | Куда | Зачем |
|---|---|---|
| `/rest/` | как есть | импорт: `GET /rest/GetUserlogin` с Basic auth |
| `/openvpn-api/` | как есть | Connect сначала проверяет `/openvpn-api/profile` |
| `/ovpn/` | со срезанием префикса | страница ссылки для браузера |

- Первые два пути обязательно в корне хоста: Connect отбрасывает путь из введённого URL.
- Ответы 401 прокси не должен подменять своими страницами ошибок.
- Если прокси режет клиентов по User-Agent, пропустите `Connect/<версия>/...` на этих путях.
- `OVPN_TRUSTED_PROXIES` - адреса прокси, которым бэкенд верит `X-Real-IP` и `X-Forwarded-For`. Прокси на хосте ходит в контейнер через шлюз docker-сети, отсюда значение по умолчанию в compose: `172.16.0.0/12`. Без этой настройки антиперебор считает всех клиентов одним IP. Прокси должен перезаписывать эти заголовки, а не пропускать присланные клиентом.

## Профили и выдача доступа

Профили кладутся в смонтированную папку (`/srv/ovpn/profiles` или `./profiles` для compose). Читать их должен uid 10001:

```bash
sudo chmod 644 /srv/ovpn/profiles/*.ovpn
```

Новые файлы подхватываются без перезапуска. Выдать доступ:

```bash
docker exec ovpn ovpn add client1.ovpn
```

```
client1.ovpn
  URL:     https://vpn.example.com
  логин:   client1
  пароль:  73SD2FHFRP
  страница: https://vpn.example.com/p/<token>
```

Пользователь ставит OpenVPN Connect, нажимает **+** -> **Import Profile** -> **URL** и вводит URL, логин и пароль. Пароль одноразовый, по умолчанию живёт 24 часа и даёт 3 импорта. Страница по ссылке - запасной путь для браузера, там есть кнопка "Скачать профиль". Под данными `add` печатает QR этой страницы: его можно сканировать камерой телефона прямо с экрана. Если страницу открыли на ПК, QR есть и на ней.

В режиме compose вместо `docker exec ovpn` используется `docker compose exec ovpn-sender`.

| Команда | Что делает |
|---|---|
| `add [файлы] [--ttl ч] [--max N] [--user логин] [--no-qr]` | выдать доступ (`0` - без ограничения, без файлов - на все профили) |
| `qr <файл или префикс токена>` | снова показать QR и данные живого доступа |
| `list [-a]` | статус выданных доступов. С `-a` - только живые, с URL, логином, паролем и ссылкой |
| `revoke <файл или префикс токена>` | отозвать |
| `cleanup` | удалить истёкшие и отозванные записи |
| `serve`, `health` | запуск сервера и проверка живости, их вызывает сам образ |

Удаление файла из `profiles/` сразу делает недействительными все выданные на него доступы. Уже импортированный профиль при этом продолжает работать: чтобы закрыть доступ, отзовите сертификат клиента на VPN-сервере.

## Переменные окружения

| Переменная | По умолчанию | Описание |
|---|---|---|
| `OVPN_DOMAIN` | пусто | включает HTTPS с сертификатом из `/etc/letsencrypt/live/<домен>/` и задаёт адрес по умолчанию |
| `OVPN_CERT`, `OVPN_KEY` | из `OVPN_DOMAIN` | пути к PEM-сертификату и ключу. Если не заданы оба, сервер работает по HTTP |
| `OVPN_BASE_URL` | `https://<OVPN_DOMAIN>` | внешний адрес страницы ссылки. За прокси с префиксом, например `https://vpn.example.com/ovpn` |
| `OVPN_TRUSTED_PROXIES` | пусто | IP или подсети прокси через запятую |
| `OVPN_PORT` | `8080` | порт внутри контейнера |
| `OVPN_PROFILES_DIR` | `/profiles` | откуда брать `.ovpn` |
| `OVPN_DATA_DIR` | `/data` | база выданных доступов (том, переживает обновление образа) |

Только для compose (`.env`): `OVPN_HOST_PORT` - порт на `127.0.0.1` хоста, `OVPN_IMAGE` - готовый образ вместо локальной сборки.

## Самостоятельная сборка

### Docker

```bash
git clone https://github.com/mikedigriz/ovpn-sender.git
cd ovpn-sender
docker build -t ovpn-sender .
```

Дальше тот же `docker run`, что в быстром старте, только с локальным тегом `ovpn-sender` вместо `mikedigriz/ovpn-sender:latest`.

### Docker Compose

`compose.yaml` собирает образ из исходников, если не задан `OVPN_IMAGE`:

```bash
cp .env.example .env
docker compose up -d --build
```

### Для нескольких архитектур в свой реестр

```bash
docker buildx create --use
docker buildx build --platform linux/amd64,linux/arm64 -t <логин>/ovpn-sender:latest --push .
```

### Без Docker

Нужен Python 3.8 или новее, зависимостей нет.

```bash
mkdir -p profiles data && cp client1.ovpn profiles/
export OVPN_PROFILES_DIR=./profiles OVPN_DATA_DIR=./data OVPN_BASE_URL=https://vpn.example.com
python3 ovpn_sender.py serve --port 8080        # HTTP за прокси
python3 ovpn_sender.py add client1.ovpn         # в другом терминале, с теми же переменными
```

Для HTTPS без прокси добавьте `OVPN_CERT` и `OVPN_KEY` (или `OVPN_DOMAIN`). Порт 443 без root недоступен, поэтому слушайте 8080 и пробросьте на него 443 файрволом.

## Публикация образа

Workflow [.github/workflows/docker.yml](.github/workflows/docker.yml) собирает образ для `amd64` и `arm64` и публикует его в Docker Hub:

- пуш в `main` - тег `latest`;
- тег `vX.Y.Z` - теги `X.Y.Z` и `X.Y`.

Настройка для своего форка:

1. Docker Hub -> Account settings -> Personal access tokens -> создать токен с правом Read & Write.
2. GitHub -> Settings -> Secrets and variables -> Actions: добавить секреты `DOCKERHUB_USERNAME` и `DOCKERHUB_TOKEN`.
3. В workflow заменить `IMAGE: mikedigriz/ovpn-sender` на своё имя.

Выпуск версии:

```bash
git tag v1.0.0 && git push origin v1.0.0
```

## Протокол

По [openvpn-rfc/webauth.md](https://github.com/OpenVPN/openvpn-rfc/blob/master/webauth.md):

1. Connect проверяет `/openvpn-api/profile`. Бэкенд отвечает 404 без заголовка `Ovpn-WebAuth`, поэтому приложение показывает поля Username и Password.
2. `GET /rest/GetUserlogin?tls-cryptv2=1&action=import` с Basic auth:
   - верные данные - 200 `text/plain` с профилем;
   - неверные - 401 и XML `<Error><Type>Authorization Required</Type>...`.

| Запрос | Описание |
|---|---|
| `GET/POST /rest/GetUserlogin`, `GetAutologin`, `GetGeneric` | Basic auth: логин из `add` и одноразовый пароль, регистр не важен |
| `/rest/GetProfileViaToken?token=<token>` | токен-ссылка `openvpn://import-profile/...` со страницы, без пароля |
| `/p/<token>` | страница для браузера |

Запросы сняты с OpenVPN Connect 3.7 (Android) и 3.9 (Windows): путь из URL отбрасывается, User-Agent имеет вид `Connect/<версия>/<платформа>`.

## Безопасность

- Внутри `.ovpn` обычно лежит приватный ключ клиента. Ссылка или пароль равносильны доступу к VPN, отсюда значения по умолчанию: 24 часа и 3 импорта. Каждый импорт любым способом расходует один.
- Ссылка `/p/<token>` - полный ключ: на странице показан пароль и есть прямое скачивание. Отправляйте её доверенным каналом. Для импорта через приложение ссылка не нужна, достаточно URL, логина и пароля.
- Пароль - 10 символов из 32-символьного алфавита (около 50 бит). После 10 неверных попыток с одного IP за 15 минут сервер отвечает 429.
- Отдаются только `*.ovpn` из `/profiles`, имена с путями отклоняются.
- TLS 1.2 и выше. TLS-рукопожатие идёт в потоке обработчика с таймаутом 30 секунд, поэтому молчащий клиент не блокирует сервер.
- Сервер построен на `http.server` из стандартной библиотеки: он не рассчитан на поток злонамеренных соединений. В открытом интернете под нагрузкой надёжнее ставить перед контейнером reverse proxy с лимитами соединений.
- В `/data/tokens.json` пишется журнал импортов (время, IP, User-Agent). Токены в логе маскируются.
- Контейнер работает от uid 10001. Compose дополнительно включает read-only FS, `cap_drop: ALL` и лимит памяти 64 МБ, те же флаги можно добавить в `docker run`.

## Лицензия

[MIT](LICENSE)
