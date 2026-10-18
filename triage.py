import json, sys
from pathlib import Path
from collections import Counter


prior = {"critical":1,"high":2,"medium":3,"low":4}

def load_json(path: Path):
    try:
        global data
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
            
    except json.decoder.JSONDecodeError as e:
        print(f"не валидный json: {e}", file=sys.stderr)
        sys.exit(2)
    except FileNotFoundError as e:
        print(f"файл не найден: {e}", file=sys.stderr)
        sys.exit(3)

    if not isinstance(data, list):
        print(f"ожидался список: {type(data).__name__}", file=sys.stderr)
        sys.exit(4)

def count_by_severity():
    print("Считываем алерты по severity и печатает их в порядке critical → high → medium → low:")
    count_severity = Counter([i["severity"].lower() for i in data])
    for i in sorted(count_severity, key=lambda x: prior.get(x, 99)):
        print(i, count_severity[i])
    print("\n")

def top_hosts(n: int = 3):
    print("Топ-3 хостов по числу алертов:")
    count_hosts = Counter([i.get("host") or "unknown" for i in data])
    for i, n in enumerate(sorted(count_hosts, key=lambda x: count_hosts.get(x, 99), reverse=True)[0:n]):
        print(i+1, n, "-", count_hosts[n])
    print("\n")

def repeated_ips(min_count: int = 2):
    print("Находим src_ip, встречающиеся 2 и более раз:")
    src=[]
    for i in data:
        if i.get("src_ip"):
            src.append(i.get("src_ip"))
    count_src=Counter(src)
    [print(f"{i[0]} встречается {i[1]} раз") for i in count_src.most_common() if i[1] >= min_count]

def urgent():
    with open(Path(__file__).parent / Path("urgent.json"), "w", encoding="utf-8") as f:
        output=[]
        for i in data:
            if i["severity"].lower() in ["high", "critical"]:
                output.append(i)
        f.write(json.dumps(output, ensure_ascii=False, indent=2))

def main() -> int:
    file = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("events.json")
    path = Path(__file__).parent / file

    load_json(path)
    count_by_severity()
    top_hosts()
    repeated_ips(3)
    urgent()

    return 0

if __name__ == "__main__":
    sys.exit(main())

#     Шаг 2. Напиши triage.py, который:

# Читает events.json с обработкой трёх ошибок: нет файла, битый JSON, внутри не список. Сообщение в stderr, разные ненулевые коды выхода.
# Считает алерты по severity и печатает их в порядке critical → high → medium → low (подсказка: раздел 7).
# Печатает топ-3 хостов по числу алертов. null или отсутствующий host считается как unknown (подсказка: разделы 4 и 9).
# Находит src_ip, встречающиеся 2 и более раз (кандидаты в источник атаки). Алерты без IP пропускает без падения.
# Записывает алерты high и critical в urgent.json с ensure_ascii=False, indent=2.
# Проверяет неуспешные пути:
# bash
# python triage.py; echo "exit=$?"
# mv events.json e.bak; python triage.py; echo "exit=$?"; mv e.bak events.json

# Потом временно испорти JSON (удали последнюю ]) и проверь снова.

# Бонус: имя файла через sys.argv[1].

# Пример из раздела 16 — твой образец по структуре, но не копируй его: набери своё. Если застрял на одном пункте больше 10 минут, пиши, дам подсказку, а не готовый ответ.