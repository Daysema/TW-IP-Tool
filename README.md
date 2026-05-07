# TW IP Tool (Telegram Bot + Docker)

## Что это
Инструмент для работы с плавающими IP Timeweb Cloud:
- **Hunter**: создаёт floating IP, оставляет только подходящие по `target_networks`, остальные удаляет.
- **Collect**: сканирует аккаунты, собирает подходящие IP и (опционально) удаляет все лишние IP.

Управление — через **Telegram‑бота** (кнопки), запуск — в **Docker**.

## Быстрый старт (Ubuntu 24)

### 1) Установите Docker + Compose
- `docker` и `docker compose` должны быть доступны.

### 2) Создайте данные в volume (локальной папкой проще)
Рекомендуемый вариант — монтировать локальную папку вместо named volume.

Пример структуры:
- `./data/accounts.json`
- `./data/config.json` (опционально)
- `./data/results/` (создастся автоматически)

#### Вариант A (рекомендуется): токены загружать прямо в боте
В этом случае достаточно создать пустой файл `./data/accounts.json`:

```json
[]
```

Потом зайдите в бота → `🛠 Токены` и добавляйте токены кнопками (по 1 / txt файлом).

#### Вариант B: заранее положить токены в файл
`./data/accounts.json`:

```json
[
  { "token": "TW_BEARER_TOKEN_1", "label": "acc1" },
  { "token": "TW_BEARER_TOKEN_2", "label": "acc2", "proxy": "socks5://user:pass@host:1080" }
]
```

`./data/config.json` (опционально):

```json
{
  "allowed_user_id": "123456789",
  "target_networks": [
    "109.73.201.0/24",
    "94.228.117.0/24",
    "81.200.148.0/24",
    "81.200.149.0/24",
    "81.200.150.0/24",
    "81.200.151.0/24"
  ],
  "target_subnets": [
    {"prefix":"109.73.201.","zone":"msk-1","loc":"МСК"},
    {"prefix":"94.228.117.","zone":"spb-3","loc":"СПБ"}
  ],
  "collect": { "delete_nontarget": true, "parallel": 5 },
  "hunter":  { "daily_limit": 100, "stop_on_found": false }
}
```

### 3) Запуск
Скопируйте файл `.env` рядом с `docker-compose.yml` и заполните его:

```bash
TG_BOT_TOKEN=123456:ABCDEF...
TG_ADMIN_USER_ID=123456789

# optional
# TG_CHAT_ID=123456789
```

Запуск:

```bash
docker compose up -d --build
```

Откройте бота в Telegram и отправьте `/start`.

## Запуск без Docker (для теста)

```bash
pip install -r requirements.txt
export TG_BOT_TOKEN=...
export TG_ADMIN_USER_ID=...
python -m tw_tool
```

