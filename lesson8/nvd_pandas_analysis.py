# nvd_pandas_analysis.py
"""
Розширений аналіз вразливостей з NVD за допомогою pandas.
Включає статистику, фільтрацію та сортування.

Що таке pandas?
Pandas - це потужна бібліотека Python для роботи з таблицями даних (як Excel, але в коді).
DataFrame - це як таблиця Excel в Python: рядки і колонки з даними.

Що робить цей скрипт:
- Завантажує вразливості з NVD
- Зберігає їх у DataFrame (таблиця pandas)
- Робить статистичний аналіз (середнє, мінімум, максимум)
- Фільтрує дані (наприклад, тільки CRITICAL)
- Сортує за оцінкою CVSS
- Зберігає результати у CSV файл
"""

# Імпортуємо необхідні модулі
import requests              # Для HTTP запитів до NVD API
import pandas as pd          # Для роботи з таблицями даних
from datetime import datetime  # Для роботи з датами


def fetch_nvd_data(keyword: str, limit: int = 50) -> pd.DataFrame:
    """
    Отримує дані з NVD та повертає pandas DataFrame.

    DataFrame - це таблиця в pandas з рядками і колонками.
    Це як Excel таблиця, але в Python коді.

    Що робить:
    1. Запитує дані з NVD API
    2. Обробляє кожну вразливість
    3. Створює список словників (кожен словник = рядок таблиці)
    4. Перетворює список у DataFrame

    Повертає:
        pd.DataFrame з колонками: cve_id, severity, score, description, published, link
    """
    # Запит до NVD API
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": keyword, "resultsPerPage": str(limit)}
    headers = {"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}

    response = requests.get(url, params=params, headers=headers, timeout=30)
    response.raise_for_status()

    # Список для зберігання всіх записів (кожен запис = рядок майбутньої таблиці)
    records = []

    # Обробляємо кожну вразливість
    for item in response.json().get("vulnerabilities", []):
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {})

        # Витягуємо CVSS дані (оцінка та рівень небезпеки)
        score, severity = None, None
        for version in ["cvssMetricV31", "cvssMetricV30"]:
            if version in metrics and metrics[version]:
                cvss = metrics[version][0].get("cvssData", {})
                score = cvss.get("baseScore")
                severity = cvss.get("baseSeverity")
                break  # Знайшли - виходимо з циклу

        # Витягуємо англійський опис
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            None
        )

        # Обробляємо дату публікації
        published = cve.get("published")
        if published:
            # Перетворюємо текст дати у об'єкт datetime
            published = datetime.fromisoformat(published.replace("Z", "+00:00"))

        # Додаємо словник з даними про вразливість
        records.append({
            "cve_id": cve.get("id"),
            "severity": severity,
            "score": score,
            "description": description,
            "published": published,
            "link": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}"
        })

    # pd.DataFrame(records) - перетворюємо список словників у таблицю pandas
    # Кожен словник стає рядком, ключі словників стають назвами колонок
    return pd.DataFrame(records)


def analyze_vulnerabilities(df: pd.DataFrame) -> None:
    """
    Виводить статистичний аналіз вразливостей з DataFrame.

    Що таке статистичний аналіз?
    Це коли ми підраховуємо різні числа про дані:
    - Скільки всього вразливостей
    - Як вони розподілені за рівнем небезпеки
    - Мінімальна, максимальна, середня оцінка
    - Топ найнебезпечніших вразливостей

    Параметри:
        df: DataFrame (таблиця pandas) з вразливостями
    """
    print("\n" + "=" * 60)
    print("СТАТИСТИКА ВРАЗЛИВОСТЕЙ")
    print("=" * 60)

    # len(df) - кількість рядків у таблиці
    print(f"\nЗагальна кількість: {len(df)}")

    # Розподіл за рівнем критичності (CRITICAL, HIGH, MEDIUM, LOW)
    print("\nРозподіл за рівнем критичності:")
    # value_counts() - підраховує скільки разів зустрічається кожне значення
    severity_counts = df["severity"].value_counts()
    for severity, count in severity_counts.items():
        print(f"  {severity or 'N/A'}: {count}")

    # Статистика CVSS Score (числові оцінки)
    # dropna() - прибирає порожні значення (NaN)
    valid_scores = df["score"].dropna()
    if not valid_scores.empty:  # Якщо є хоч якісь оцінки
        print(f"\nCVSS Score:")
        print(f"  Мінімальний: {valid_scores.min()}")    # Найменша оцінка
        print(f"  Максимальний: {valid_scores.max()}")   # Найбільша оцінка
        print(f"  Середній: {valid_scores.mean():.2f}")  # Середнє арифметичне, :.2f = 2 знаки після коми

    # Топ-5 найкритичніших вразливостей
    print("\nТоп-5 найкритичніших вразливостей:")
    # nlargest(5, "score") - вибирає 5 рядків з найбільшими значеннями у колонці "score"
    # [["cve_id", "score", "severity"]] - вибираємо тільки ці колонки
    critical = df.nlargest(5, "score")[["cve_id", "score", "severity"]]
    # iterrows() - проходить по рядках DataFrame
    for _, row in critical.iterrows():
        print(f"  {row['cve_id']}: {row['score']} ({row['severity']})")


def main():
    """
    Головна функція - демонстрація можливостей pandas для аналізу вразливостей.

    Що робить:
    1. Завантажує вразливості для nginx з NVD
    2. Робить статистичний аналіз
    3. Фільтрує тільки високі та критичні вразливості
    4. Сортує за CVSS score (від найнебезпечніших)
    5. Зберігає у CSV файл
    """
    keyword = "nginx"  # Що шукаємо
    output_file = "nginx_vulnerabilities.csv"  # Куди зберігаємо

    try:
        print(f"Завантаження даних для '{keyword}'...")
        # Отримуємо DataFrame (таблицю) з вразливостями
        df = fetch_nvd_data(keyword, limit=50)

        # Перевіряємо чи є дані
        if df.empty:  # empty означає "порожній"
            print("Вразливостей не знайдено.")
            return

        # Робимо статистичний аналіз
        analyze_vulnerabilities(df)

        # Фільтрація: вибираємо тільки CRITICAL та HIGH
        # isin(["CRITICAL", "HIGH"]) перевіряє чи значення в списку
        # df[умова] - вибирає тільки рядки де умова True
        high_risk = df[df["severity"].isin(["CRITICAL", "HIGH"])]
        print(f"\nВисокий ризик (CRITICAL + HIGH): {len(high_risk)}")

        # Сортування за score (від найвищого до найнижчого)
        # ascending=False означає "від більшого до меншого" (за замовчуванням навпаки)
        # na_position="last" означає "порожні значення в кінець"
        df_sorted = df.sort_values("score", ascending=False, na_position="last")

        # Збереження у CSV файл
        # index=False означає "не зберігати номери рядків"
        # encoding="utf-8" - кодування для підтримки українських букв
        df_sorted.to_csv(output_file, index=False, encoding="utf-8")
        print(f"\nДані збережено у {output_file}")

    except requests.exceptions.RequestException as err:
        # Якщо помилка з інтернетом
        print(f"Помилка API: {err}")


# Запускаємо програму
if __name__ == "__main__":
    main()
