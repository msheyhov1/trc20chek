# Артефакты проверки источников (17.09.2026)

Материалы к разделу 5 `ROADMAP.md`. Здесь только то, что сделано в рамках проекта:
чужие зеркала документации и чужой код в репозиторий не копировались.

| Файл | Что это | Как воспроизвести |
|---|---|---|
| `keccak_selectors.py` | Чистый Python Keccak-256 с самопроверкой; печатает селекторы функций контракта USDT-TRC20 | `python docs/research/keccak_selectors.py` |
| `ofac_sanctioned_trx_2026-09-17.txt` | Снимок `sanctioned_addresses_TRX.txt` из `0xB10C/ofac-sanctioned-digital-currency-addresses` (ветка `lists`) на дату проверки: 254 адреса | `curl -sS https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_TRX.txt` |

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
