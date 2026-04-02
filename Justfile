sync:
    uv sync --all-groups --all-packages

build:
    docker compose build

bash:
    docker compose run -it --rm server bash

manage *args:
    docker compose run --rm server python manage.py {{args}}

shell:
    docker compose run -it --rm server python manage.py shell

mypy:
    docker compose run --rm server mypy

makemigrations:
    docker compose run --rm server python manage.py makemigrations

createsuperuser:
    docker compose run --rm server python manage.py createsuperuser

migrate:
    docker compose run --rm server python manage.py migrate

test *args:
    docker compose run --rm server pytest {{args}}

collectstatic:
    docker compose run --rm server python manage.py collectstatic --noinput

coverage:
    open htmlcov/index.html

celery-logs:
    docker compose logs -f celery-worker celery-beat
