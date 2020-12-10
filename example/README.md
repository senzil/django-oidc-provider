# Example Project

On this example you'll be running your own OIDC provider in a second. This is a Django app with all the necessary things to work with `senzil-django-oidc-provider` package.

## Setup & Running

- [Manually](#manually)
- [Using Docker](#using-docker)

### Manually

Setup project environment with [virtualenv](https://virtualenv.pypa.io) and [pip](https://pip.pypa.io).

```bash
$ virtualenv -p /usr/bin/python3 project_env

$ source project_env/bin/activate

$ git clone https://github.com/senzil/senzil-django-oidc-provider.git
$ cd senzil-django-oidc-provider/example
$ pip install -r requirements.txt
```

Run your provider.

```bash
$ python manage.py migrate
$ python manage.py creatersakey
$ python manage.py createsuperuser
$ python manage.py runserver
```

Open your browser and go to `http://localhost:8000`. Uala!

### Using Docker

Build and run the container.

```bash
$ docker build -t senzil-django-oidc-provider .
$ docker run -d -p 8000:8000 senzil-django-oidc-provider
```

## Install package for development

After you run `pip install -r requirements.txt`.
```bash
# Remove pypi package.
$ pip uninstall senzil-django-oidc-provider

# Go back to senzil-django-oidc-provider/ folder and add the package on editable mode.
$ cd ..
$ pip install -e .
```
