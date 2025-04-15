--
-- Файл сгенерирован с помощью SQLiteStudio v3.4.4 в Вс фев 2 09:24:47 2025
--
-- Использованная кодировка текста: System
--
PRAGMA foreign_keys = off;
BEGIN TRANSACTION;

-- Таблица: active_user
CREATE TABLE IF NOT EXISTS active_user (
    id INTEGER PRIMARY KEY
             REFERENCES users (id) 
             NOT NULL
             UNIQUE
);


-- Таблица: history
CREATE TABLE IF NOT EXISTS history (
    id      INTEGER  PRIMARY KEY AUTOINCREMENT
                     UNIQUE
                     NOT NULL,
    date    DATETIME DEFAULT (datetime(CURRENT_TIMESTAMP, 'localtime') ) 
                     NOT NULL,
    ip_list TEXT     NOT NULL,
    user_id INTEGER  NOT NULL
                     REFERENCES users (id) 
);

-- Таблица: ip_addresses
CREATE TABLE IF NOT EXISTS ip_addresses (
    id         INTEGER UNIQUE,
    ip_address TEXT    NOT NULL
                       UNIQUE,
    PRIMARY KEY (
        id AUTOINCREMENT
    )
);

-- Таблица: users
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER  PRIMARY KEY AUTOINCREMENT
                           UNIQUE,
    username      TEXT     UNIQUE
                           NOT NULL,
    password      TEXT     NOT NULL,
    enabled       INTEGER  DEFAULT (0) 
                           NOT NULL ON CONFLICT ABORT
                           CHECK ( (enabled IN (0, 1) ) ),
    cn            TEXT     NOT NULL,
    email         TEXT     NOT NULL
                           UNIQUE,
    register_date DATETIME NOT NULL
                           DEFAULT (datetime(CURRENT_TIMESTAMP, 'localtime') ),
    is_admin      INTEGER  CHECK ( (enabled IN (0, 1) ) ) 
                           DEFAULT (0) 
                           NOT NULL
);

INSERT OR IGNORE INTO users (id, username, password, enabled, cn, email, is_admin) VALUES (1, 'admin', '$2b$12$iGlcqKwJybrrnWczsB3rwe6lS1VoeIOGH3e1s4GcI0lpkJ7y8Zciq', 1, 'admin', 'admin@local', 1);

COMMIT TRANSACTION;
PRAGMA foreign_keys = on;
