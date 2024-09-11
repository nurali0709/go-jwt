
# Мой проект на Go с использованием Gin

## Описание

Этот проект создан с использованием языка программирования Go и веб-фреймворка Gin. В проекте используется база данных PostgreSQL и JWT для аутентификации.

## Необходимые компоненты

Перед запуском проекта убедитесь, что у вас установлены следующие компоненты:

- Go (версия 1.18+)
- PostgreSQL (версия 12+)
- Git

## Настройка

### 1. Клонирование репозитория

```bash
git clone https://github.com/nurali0709/go-jwt.git
cd go-jwt
```

### 2. Установка зависимостей

```bash
go mod tidy
```

### 3. Переменные окружения

Создайте файл `.env` в корневом каталоге проекта. Этот файл будет содержать переменные окружения, включая учетные данные для PostgreSQL и секретный ключ для JWT.

Пример содержания файла `.env`:

```dotenv
DB="postgresql://user:pass@localhost/users?sslmode=disable"
SECRET="my-secret"
```

### 4. Запуск приложения

Чтобы запустить приложение:

```bash
go run main.go
```

Сервер должен запуститься на `http://localhost:8080`.


## Использование

Вы можете взаимодействовать с API с помощью инструментов, таких как `curl` или Postman. Обратитесь к документации проекта для получения информации о доступных конечных точках и их использовании.
