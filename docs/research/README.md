# Артефакты проверки источников (17.09.2026)

Материалы к разделу 5 `ROADMAP.md`. Здесь только то, что сделано в рамках проекта:
чужие зеркала документации и чужой код в репозиторий не копировались.

| Файл | Что это | Как воспроизвести |
|---|---|---|
| `keccak_selectors.py` | Чистый Python Keccak-256 с самопроверкой; печатает селекторы функций контракта USDT-TRC20 | `python docs/research/keccak_selectors.py` |
| `../../core/data/ofac_sanctioned_trx.txt` | Снимок санкционных TRON-адресов: объединение файлов `TRX`, `USDT`, `USDC`, `XBT` из `0xB10C/ofac-sanctioned-digital-currency-addresses` (ветка `lists`), 334 адреса на 22.09.2026. Лежит внутри пакета `core`, потому что используется как запасной список в рантайме (`core/providers/ofac.py`) и должен попадать в образ | см. `ofac_assets.md` |
| `ofac_assets.md` | Замер, из которого видно, что фид разложен по активам, а не по сетям: 80 санкционных TRON-адресов лежат в файлах `USDT` и `XBT` и при чтении одного `TRX` были невидимы | команды внутри файла |

Ключевой результат скрипта: селектор `isBlackListed(address)` = `0xe47d6060`.
Строчный вариант `isBlacklisted(address)` даёт `0xfe575a87` — это другая функция,
у контракта Tether её нет. Регистр `L` обязателен.

Официальная документация TronScan и TronGrid читалась через дословное GitHub-зеркало
`hiddengogeta/tron-docs-markdown` (страницы Account, Transactions and Transfers,
Security Service API, API Keys, TronGrid) — сами сайты документации из окружения
проверки были недоступны. Продакшн-код, по которому подтверждён вызов `isBlackListed`:
`horizontalsystems/unstoppable-wallet-ios`, `horizontalsystems/unstoppable-wallet-android`,
`emercoin/swap`, `delphian/tronrelic`, `agenthill/vaultpilot-mcp`,
`blockrockettech/stablemoney.dev`, `lingxi9999/chain-sentinel`.
