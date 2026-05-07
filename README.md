# TW-IP-Tool (Telegram Bot + Docker)

## 1) Установите Docker на сервер (Ubuntu 24)

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
```

Проверка:

```bash
docker --version
docker compose version
```

## 2) Установите бота на сервер

### 2.1 Скачайте проект

```bash
sudo apt install -y git
git clone https://github.com/Daysema/TW-IP-Tool.git
cd TW-IP-Tool
```

### 2.2 Подготовьте данные
Создайте папку `data` (она примонтируется в контейнер как `/data`):

```bash
mkdir -p data/results
echo "[]" > data/accounts.json
```

Токены можно загружать прямо в боте через меню `🛠 Токены`.

### 2.3 Создайте `.env` и заполните
Скопируйте пример и впишите свои данные:

```bash
cp .env.example .env
nano .env
```

Нужно заполнить:
- `TG_BOT_TOKEN` — токен бота от `@BotFather`
- `TG_ADMIN_USER_ID` — ваш Telegram user id (можно узнать у `@userinfobot`)

Опционально:
- `TG_CHAT_ID` — если хотите, чтобы логи всегда шли в конкретный чат

## 3) Запуск бота

```bash
docker compose up -d --build
docker compose logs -f
```

В Telegram напишите боту `/start`.

Остановить:

```bash
docker compose down
```

## 4) Как обновить бота

```bash
cd TW-IP-Tool
git pull
docker compose up -d --build
```

## Использование бота (кратко)

Откройте Telegram и отправьте боту команду `/start` — появится меню.

### 🛠 Токены
- **➕ Добавить 1**: отправьте 1 токен Timeweb (одной строкой).
- **➕ Добавить пачкой**: отправьте `.txt` файл с токенами (по одному на строку) или вставьте текстом.
- **🔎 Проверка на дубли**: удаляет дубликаты токенов (оставляет по 1 на каждый).
- **✅ Проверка правильности**: удаляет некорректные токены (с пробелами/переносами).
- **🧹 Удалить токены**: очищает список токенов.

### Поиск IP
Запускает цикл создания floating IP по аккаунтам (по очереди). Если IP:
- **не подходит** под целевые подсети — удаляется
- **подходит** — остаётся

Токены с лимитами/недостатком средств попадают в blacklist на время (и временно пропускаются).

### Проверка аккаунтов
Сканирует все аккаунты и удаляет **лишние** floating IP (которые не подходят по целевым подсетям).

### Статус
Показывает текущую ситуацию:
- запущен/остановлен поиск и проверка
- сколько создано, сколько подходит, сколько удалено
- сколько токенов в чёрном списке


