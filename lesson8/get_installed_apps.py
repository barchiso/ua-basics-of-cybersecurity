# get_installed_apps.py
"""
Кросплатформовий скрипт для отримання списку встановлених програм.
Працює на Windows, macOS та Linux.

Що робить цей скрипт:
- Автоматично визначає вашу операційну систему (Windows, macOS або Linux)
- Знаходить всі встановлені програми на комп'ютері
- Зберігає список програм у текстовий файл
- Показує перші 20 програм на екрані
"""

# Імпортуємо (підключаємо) необхідні модулі - це готові інструменти Python
import subprocess  # Дозволяє запускати системні команди (як в командному рядку)
import platform    # Дає інформацію про операційну систему
import sys         # Для роботи з системними функціями (вихід з програми, помилки)
from typing import Optional  # Для підказок типів даних (необов'язково, але корисно)


def get_windows_apps() -> list[str]:
    """
    Отримує список програм на Windows через PowerShell.

    Що робить функція:
    1. Запускає команду PowerShell для читання реєстру Windows
    2. Шукає інформацію про встановлені програми в двох місцях реєстру
    3. Повертає відсортований список назв програм
    """
    # Створюємо команду для PowerShell (це як "мова" Windows)
    # Команда йде в реєстр (база даних Windows) і шукає встановлені програми
    command = [
        "powershell", "-Command",  # Говоримо, що це команда PowerShell
        "Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, "
        "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | "
        "Select-Object DisplayName | Where-Object { $_.DisplayName } | "
        "Sort-Object DisplayName | ForEach-Object { $_.DisplayName }"
    ]

    # subprocess.run() - запускає команду і чекає результату
    result = subprocess.run(
        command,
        capture_output=True,  # Зберігаємо результат команди
        text=True,            # Результат як текст (не байти)
        encoding="utf-8",     # Кодування тексту (щоб підтримувати українські букви)
        errors="ignore"       # Ігноруємо помилки кодування
    )

    # Перевіряємо, чи команда виконалась успішно
    # returncode == 0 означає "все добре", інше число = помилка
    if result.returncode != 0:
        raise RuntimeError(f"PowerShell error: {result.stderr}")

    # Обробляємо результат:
    # 1. result.stdout - текст, який повернула команда
    # 2. .split("\n") - ділимо на окремі рядки
    # 3. line.strip() - прибираємо пробіли на початку і кінці
    # 4. if line.strip() - беремо тільки непорожні рядки
    apps = [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]

    # sorted(set(apps)) - прибираємо дублікати (set) і сортуємо по алфавіту (sorted)
    return sorted(set(apps))


def get_macos_apps() -> list[str]:
    """
    Отримує список .app програм на macOS.

    Що робить функція:
    1. Шукає всі файли з розширенням .app у папці Applications
    2. Витягує назви програм з повних шляхів
    3. Повертає відсортований список назв
    """
    # Команда find шукає файли (як пошук у Finder на Mac)
    # /Applications - папка де зберігаються програми на Mac
    # -maxdepth 2 - шукаємо не глибше ніж на 2 рівні вкладеності
    # -name '*.app' - шукаємо тільки файли що закінчуються на .app
    # -type d - шукаємо директорії (на Mac програми це теж папки)
    # 2>/dev/null - ховаємо повідомлення про помилки
    command = "find /Applications -maxdepth 2 -name '*.app' -type d 2>/dev/null"

    # Запускаємо команду через термінал
    result = subprocess.run(
        command,
        shell=True,           # Виконуємо як команду терміналу
        capture_output=True,  # Зберігаємо результат
        text=True             # Результат як текст
    )

    # Створюємо порожній список для зберігання назв програм
    apps = []

    # Проходимо по кожному рядку результату (кожен рядок = шлях до програми)
    for path in result.stdout.strip().split("\n"):
        if path:  # Якщо рядок не порожній
            # Приклад: "/Applications/Safari.app" -> "Safari"
            # path.split("/") - ділимо шлях на частини: ["", "Applications", "Safari.app"]
            # [-1] - беремо останній елемент: "Safari.app"
            # .replace(".app", "") - прибираємо ".app": "Safari"
            app_name = path.split("/")[-1].replace(".app", "")
            apps.append(app_name)  # Додаємо назву до списку

    # Прибираємо дублікати та сортуємо
    return sorted(set(apps))


def get_linux_apps() -> list[str]:
    """
    Отримує список пакетів на Linux (Debian/Ubuntu або Fedora/RedHat).

    Що робить функція:
    1. Спочатку пробує команду для Ubuntu/Debian (dpkg-query)
    2. Якщо не вдається, пробує команду для Fedora/RedHat (rpm)
    3. Повертає відсортований список пакетів
    """
    # dpkg-query - інструмент для Debian/Ubuntu систем
    # -W - показати встановлені пакети
    # -f=${Package}\n - формат виводу (тільки назва пакету)
    command = ["dpkg-query", "-W", "-f=${Package}\n"]

    try:
        # Спробуємо запустити команду для Ubuntu/Debian
        result = subprocess.run(
            command,
            capture_output=True,  # Зберігаємо результат
            text=True,            # Результат як текст
            check=True            # Якщо помилка - викинути виняток
        )
        # Обробляємо результат: розділяємо на рядки і прибираємо пробіли
        apps = [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
        return sorted(apps)
    except FileNotFoundError:
        # FileNotFoundError означає, що dpkg-query не знайдено
        # Це значить що це не Debian/Ubuntu, а можливо Fedora/RedHat

        # rpm - інструмент для RedHat/Fedora систем
        # -qa - показати всі встановлені пакети
        # --qf "%{NAME}\n" - формат виводу (тільки назва)
        command = ["rpm", "-qa", "--qf", "%{NAME}\n"]
        result = subprocess.run(command, capture_output=True, text=True)
        apps = [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
        return sorted(apps)


def get_installed_apps() -> Optional[list[str]]:
    """
    Визначає операційну систему та повертає список програм.

    Що робить функція:
    1. Дізнається яка у вас ОС (Windows, Mac чи Linux)
    2. Викликає відповідну функцію для цієї ОС
    3. Повертає список програм
    """
    # platform.system() повертає назву ОС: "Windows", "Darwin" (Mac) або "Linux"
    system = platform.system()

    # Перевіряємо яка ОС і викликаємо відповідну функцію
    if system == "Windows":
        return get_windows_apps()
    elif system == "Darwin":  # macOS називається "Darwin" всередині системи
        return get_macos_apps()
    elif system == "Linux":
        return get_linux_apps()
    else:
        # Якщо ОС незнайома - виводимо помилку
        raise OSError(f"Непідтримувана ОС: {system}")


def main():
    """
    Головна функція програми - запускається при старті скрипта.

    Що робить:
    1. Показує інформацію про вашу ОС
    2. Знаходить всі програми
    3. Виводить перші 20 на екран
    4. Зберігає повний список у текстовий файл
    """
    try:
        # Виводимо інформацію про систему
        print(f"Операційна система: {platform.system()} {platform.release()}")
        print("-" * 50)  # Лінія-роздільник (50 дефісів)

        # Отримуємо список програм
        apps = get_installed_apps()

        # len(apps) - кількість елементів у списку
        print(f"Знайдено програм: {len(apps)}\n")

        # Виводимо перші 20 програм
        # enumerate(apps[:20], 1) - нумерує список починаючи з 1
        # apps[:20] означає "перші 20 елементів списку"
        for i, app in enumerate(apps[:20], 1):
            # {i:3} означає "число i шириною 3 символи" (для рівного вирівнювання)
            print(f"{i:3}. {app}")

        # Якщо програм більше 20 - повідомляємо про це
        if len(apps) > 20:
            print(f"\n... та ще {len(apps) - 20} програм")

        # Зберігаємо всі програми у файл
        # "w" означає "write" (запис)
        # encoding="utf-8" - щоб підтримувати українські букви
        with open("installed_apps.txt", "w", encoding="utf-8") as f:
            # "\n".join(apps) - з'єднує всі програми, кожну з нового рядка
            f.write("\n".join(apps))
        print(f"\nПовний список збережено у installed_apps.txt")

    except Exception as err:
        # Якщо сталася будь-яка помилка - виводимо її
        # sys.stderr - стандартний потік для помилок
        print(f"Помилка: {err}", file=sys.stderr)
        sys.exit(1)  # Завершуємо програму з кодом помилки 1


# Ця конструкція означає: "якщо цей файл запущено напряму (не імпортовано)"
if __name__ == "__main__":
    main()  # Запускаємо головну функцію
