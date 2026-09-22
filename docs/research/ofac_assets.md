# Фид OFAC разложен по активам, а не по сетям (замер 22.09.2026)

## Вопрос

`core/providers/ofac.py` читал один файл — `sanctioned_addresses_TRX.txt`.
Вопрос: все ли санкционные TRON-адреса в нём.

## Как воспроизвести

```bash
base=https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_
for a in TRX USDT USDC ETH XBT; do curl -sS -o "$a.txt" "$base$a.txt"; done

python3 - <<'PY'
import pathlib
from core.models import is_valid_trc20_address
per = {}
for a in ("TRX", "USDT", "USDC", "ETH", "XBT"):
    lines = [l.strip() for l in pathlib.Path(f"{a}.txt").read_text().splitlines()
             if l.strip() and not l.startswith("#")]
    per[a] = (len(lines), {l for l in lines if is_valid_trc20_address(l)})
trx = per["TRX"][1]
for a, (n, tron) in per.items():
    print(f"{a:5} записей {n:4}  TRON-формата {len(tron):4}  нет в TRX: {len(tron - trx)}")
PY
```

## Результат

| Файл актива | Записей | Из них TRON-формата | Нет в файле TRX |
|---|---|---|---|
| `TRX`  | 254 | 254 | — |
| `USDT` |  94 |  79 | **79** |
| `USDC` |   2 |   0 | 0 |
| `ETH`  | 120 |   0 | 0 |
| `XBT`  | 532 |   1 | **1** |

Объединение: **334** TRON-адреса против 254 при чтении одного файла TRX.
Все 80 дополнительных проходят base58check — это настоящие адреса, а не мусор
разметки, и ни один из них не встречался в файле TRX.

## Вывод

OFAC перечисляет адрес вместе с активом, который через него шёл, поэтому
TRON-адреса попадают в файл USDT: на TRON основной оборот именно в USDT.
Чтение одного файла TRX означало, что 80 санкционных адресов проходили проверку
без пометки «санкционный напрямую».

Провайдер читает список файлов из `OFAC_ASSETS` (по умолчанию `TRX,USDT,USDC,XBT`)
и объединяет множества, фильтруя каждую строку через `is_valid_trc20_address` —
в файлах по активам лежат адреса и других сетей.

Живым результат считается, только если скачались все файлы: неполное объединение
— это молча пропавшие сотни адресов, а вшитый снимок отстаёт максимум на дни и
его источник виден в `provider_status`.
