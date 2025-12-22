# nvd_basic.py
"""
Базовий запит до NVD API для пошуку вразливостей.
Використання: python nvd_basic.py

Що таке NVD?
NVD (National Vulnerability Database) - це база даних вразливостей у програмному забезпеченні.
Це як енциклопедія всіх знайдених проблем безпеки у різних програмах.

Що робить цей скрипт:
- Підключається до NVD через інтернет
- Шукає інформацію про вразливості у програмі (наприклад, OpenSSH)
- Виводить перші 5 знайдених вразливостей
"""

# requests - бібліотека для роботи з інтернетом (HTTP запити)
# Це як браузер, але для програм
import requests


def search_nvd(keyword: str, limit: int = 5) -> dict:
    """
    Пошук вразливостей у NVD за ключовим словом.

    Що робить:
    1. Надсилає запит до NVD API (сервер у інтернеті)
    2. Отримує дані про вразливості у форматі JSON
    3. Повертає ці дані для подальшої обробки

    Параметри (що передаємо функції):
        keyword: Назва програми для пошуку (наприклад, "OpenSSH")
        limit: Скільки максимум результатів хочемо отримати

    Що повертає:
        Словник (dict) з даними про вразливості у форматі JSON
    """
    # URL - адреса API сервера NVD в інтернеті
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # params - параметри запиту (що ми хочемо знайти)
    # Це як форма пошуку на веб-сайті
    params = {
        "keywordSearch": keyword,           # Що шукаємо
        "resultsPerPage": str(limit)        # Скільки результатів на сторінці
    }

    # headers - додаткова інформація про наш запит
    # User-Agent - "ім'я" нашої програми (щоб сервер знав хто запитує)
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"
    }

    # requests.get() - надсилаємо GET запит (запитуємо дані)
    # timeout=30 - якщо сервер не відповість за 30 секунд, вважаємо що помилка
    response = requests.get(url, params=params, headers=headers, timeout=30)

    # raise_for_status() - якщо сервер повернув помилку (404, 500 і т.д.) - викинути виняток
    response.raise_for_status()

    # .json() - перетворює відповідь сервера у словник Python
    return response.json()


def main():
    """
    Головна функція - демонстрація роботи з NVD API.

    Що робить:
    1. Шукає вразливості для OpenSSH
    2. Виводить загальну кількість знайдених вразливостей
    3. Показує перші 5 з описами
    """
    try:
        # Шукаємо вразливості для OpenSSH
        data = search_nvd("OpenSSH", limit=5)

        # .get('totalResults', 0) - отримати значення за ключем 'totalResults'
        # якщо ключа немає - повернути 0
        print(f"Знайдено вразливостей: {data.get('totalResults', 0)}")
        print("-" * 50)  # Лінія-роздільник

        # Проходимо по всіх знайдених вразливостях
        # .get("vulnerabilities", []) - отримати список вразливостей
        # якщо його немає - повернути порожній список []
        for item in data.get("vulnerabilities", []):
            # Витягуємо інформацію про CVE (вразливість)
            cve = item.get("cve", {})
            cve_id = cve.get("id", "N/A")  # ID вразливості (наприклад, CVE-2023-1234)

            # Отримуємо опис англійською мовою
            descriptions = cve.get("descriptions", [])
            # next() - знаходить перший опис англійською
            # якщо не знайдено - повертає "No description"
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description"
            )

            # Виводимо ID та перші 100 символів опису
            print(f"\n{cve_id}")
            print(f"  {description[:100]}...")  # [:100] - перші 100 символів

    # Обробка помилок (якщо щось пішло не так)
    except requests.exceptions.HTTPError as err:
        # HTTPError - помилка від сервера (404, 500 і т.д.)
        print(f"HTTP помилка: {err}")
    except requests.exceptions.Timeout:
        # Timeout - сервер не відповів вчасно
        print("Помилка: перевищено час очікування запиту")
    except requests.exceptions.RequestException as err:
        # RequestException - будь-яка інша помилка з'єднання
        print(f"Помилка з'єднання: {err}")


# Запускаємо головну функцію, якщо файл запущено напряму
if __name__ == "__main__":
    main()
