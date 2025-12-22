# nvd_to_csv.py
"""
Пошук вразливостей у NVD та збереження у CSV файл.
Включає: CVE ID, Severity, Score, опис, дату публікації.

Що робить цей скрипт:
- Шукає вразливості для програми (наприклад, OpenSSH)
- Збирає детальну інформацію: ID, рівень небезпеки, оцінку, опис
- Зберігає все у CSV файл (як таблиця Excel)
- Показує статистику критичних вразливостей
"""

# Імпортуємо необхідні модулі
import csv                      # Для роботи з CSV файлами (таблиці)
import requests                 # Для інтернет-запитів до NVD API
from datetime import datetime   # Для роботи з датами
from typing import Optional     # Для вказівки типів (може бути None)


def get_cvss_info(metrics: dict) -> tuple[Optional[float], Optional[str]]:
    """
    Витягує CVSS score та severity з метрик вразливості.

    Що таке CVSS?
    CVSS (Common Vulnerability Scoring System) - система оцінки вразливостей.
    - Score (оцінка): число від 0 до 10 (10 = найнебезпечніше)
    - Severity (рівень): CRITICAL, HIGH, MEDIUM, LOW

    Що робить функція:
    1. Шукає CVSS метрики у різних версіях (v3.1, v3.0, v2)
    2. Бере першу знайдену версію
    3. Повертає оцінку та рівень небезпеки

    Повертає:
        tuple з двох значень: (оцінка, рівень) або (None, None) якщо не знайдено
    """
    # Пробуємо різні версії CVSS (спочатку новіші, потім старіші)
    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        # Перевіряємо чи є ця версія в metrics
        if version in metrics and metrics[version]:
            # Беремо перший елемент списку [0] та витягуємо cvssData
            cvss_data = metrics[version][0].get("cvssData", {})
            # Повертаємо tuple (кортеж) з двох значень
            return (
                cvss_data.get("baseScore"),      # Оцінка (число)
                cvss_data.get("baseSeverity")    # Рівень (текст)
            )
    # Якщо не знайшли жодної версії - повертаємо None, None
    return None, None


def fetch_vulnerabilities(keyword: str, limit: int = 20) -> list[dict]:
    """
    Отримує список вразливостей з NVD API та форматує їх.

    Що робить:
    1. Надсилає запит до NVD
    2. Обробляє кожну вразливість
    3. Витягує: ID, severity, score, опис, дату, посилання
    4. Повертає список словників (кожен словник = одна вразливість)
    """
    # Адреса API та параметри запиту
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": keyword, "resultsPerPage": str(limit)}
    headers = {"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}

    # Надсилаємо запит
    response = requests.get(url, params=params, headers=headers, timeout=30)
    response.raise_for_status()  # Перевіряємо на помилки

    # Список для зберігання результатів
    results = []

    # Обробляємо кожну вразливість
    for item in response.json().get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "N/A")  # CVE ID (наприклад, CVE-2023-1234)

        # Витягуємо опис англійською
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available"
        )

        # Обробляємо дату публікації
        # Перетворюємо з формату ISO (2023-01-15T10:30:00.000Z) у простий (2023-01-15)
        published = cve.get("published", "")
        if published:
            # fromisoformat() - перетворює текст у об'єкт дати
            published = datetime.fromisoformat(published.replace("Z", "+00:00"))
            # strftime() - форматує дату як "рік-місяць-день"
            published = published.strftime("%Y-%m-%d")

        # Отримуємо CVSS оцінку та рівень небезпеки
        score, severity = get_cvss_info(cve.get("metrics", {}))

        # Додаємо словник з інформацією про вразливість
        results.append({
            "CVE ID": cve_id,
            "Severity": severity or "N/A",           # or "N/A" = якщо None, то "N/A"
            "Score": score or "N/A",
            "Description": description,
            "Published": published or "N/A",
            "Link": f"https://nvd.nist.gov/vuln/detail/{cve_id}"  # Посилання на деталі
        })

    return results


def save_to_csv(data: list[dict], filename: str) -> None:
    """
    Зберігає дані у CSV файл (як таблиця Excel).

    CSV - Comma-Separated Values (значення розділені комами)
    Це текстовий формат для таблиць, який можна відкрити в Excel, Google Sheets і т.д.

    Що робить:
    1. Перевіряє чи є дані
    2. Створює CSV файл
    3. Записує заголовки колонок
    4. Записує всі рядки з даними
    """
    # Якщо список data порожній - виходимо
    if not data:
        print("Немає даних для збереження.")
        return

    # fieldnames - назви колонок у таблиці
    fieldnames = ["CVE ID", "Severity", "Score", "Description", "Published", "Link"]

    # Відкриваємо файл для запису
    # "w" - режим запису, newline="" - для правильного форматування CSV
    with open(filename, "w", newline="", encoding="utf-8") as f:
        # csv.DictWriter - інструмент для запису словників у CSV
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()    # Записуємо рядок з назвами колонок
        writer.writerows(data)  # Записуємо всі рядки даних

    print(f"Збережено {len(data)} записів у {filename}")


def main():
    """
    Головна функція - демонстрація роботи скрипта.

    Що робить:
    1. Шукає вразливості для OpenSSH
    2. Зберігає результати у CSV файл
    3. Показує статистику критичних вразливостей
    """
    keyword = "OpenSSH"  # Що шукаємо
    filename = "openssh_vulnerabilities.csv"  # Куди зберігаємо

    try:
        print(f"Пошук вразливостей для '{keyword}'...")
        # Отримуємо список вразливостей
        vulnerabilities = fetch_vulnerabilities(keyword, limit=20)

        # Зберігаємо у CSV файл
        save_to_csv(vulnerabilities, filename)

        # Фільтруємо тільки критичні вразливості
        # List comprehension: [елемент for елемент in список if умова]
        critical = [v for v in vulnerabilities if v["Severity"] == "CRITICAL"]

        # Якщо є критичні - показуємо їх
        if critical:
            print(f"\nКритичних вразливостей: {len(critical)}")
            # [:5] - показуємо максимум 5
            for v in critical[:5]:
                print(f"  {v['CVE ID']} (Score: {v['Score']})")

    except requests.exceptions.RequestException as err:
        # Якщо помилка з інтернетом
        print(f"Помилка API: {err}")


# Запускаємо програму
if __name__ == "__main__":
    main()
