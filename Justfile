sync:
    uv sync --all-groups --all-packages

build:
    docker compose build django celery-worker celery-beat agent

shell:
    docker compose run -it --rm django python manage.py shell

mypy:
    docker compose run --rm django mypy

makemigrations:
    docker compose run --rm django python manage.py makemigrations

createsuperuser:
    docker compose run --rm django python manage.py createsuperuser

migrate:
    docker compose run --rm django python manage.py migrate

test *args:
    docker compose run --rm django pytest {{args}}

coverage:
    open htmlcov/index.html

celery-logs:
    docker compose logs -f celery-worker celery-beat
