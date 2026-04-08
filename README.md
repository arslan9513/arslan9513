# SentinelAI Defender (PyQt5)

`SentinelAI Defender` — десктопное приложение на Python + PyQt5 для анализа системы и выявления потенциально вредоносных программ с ИИ-интеграцией.

## Что умеет

- 8+ функциональных страниц (для демонстрации и скриншотов):
  1. Dashboard
  2. Quick Scan
  3. Deep Scan
  4. Process Monitor
  5. Quarantine
  6. AI Assistant
  7. Reports
  8. Settings
- Быстрый и глубокий скан файловой системы.
- Эвристики: сигнатуры, подозрительные расширения, высокая энтропия, известные индикаторы.
- Монитор процессов (PID/CPU/RAM/командная строка).
- Карантин подозрительных файлов.
- Генерация отчётов в JSON.
- ИИ-анализ найденных объектов (локальный fallback + внешняя интеграция по API-ключу).

## Установка

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
```

## Запуск

```bash
python main.py
```

## ИИ-интеграция (опционально)

В `Settings` можно указать:
- API Key
- Endpoint (например, совместимый с OpenAI Chat Completions)
- Модель

Если ключ не указан, приложение использует локальный rule-based AI fallback.

## Важно

Это учебный/демо-проект. Не заменяет профессиональные EDR/антивирусные решения.
