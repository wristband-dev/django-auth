import django
from django.conf import settings
from django.core.management import call_command


def pytest_configure():
    """Configure Django settings for tests."""

    class URLConf:
        urlpatterns = []

    settings.configure(
        DEBUG=True,
        DATABASES={
            "default": {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": ":memory:",
            }
        },
        INSTALLED_APPS=[
            "django.contrib.auth",
            "django.contrib.contenttypes",
            "django.contrib.sessions",
        ],
        WRISTBAND_SESSION_SECRET="test-wristband-secret-32-chars-long!!",
        SESSION_ENGINE="wristband.django_auth.sessions.backends.encrypted_cookies",
        SECRET_KEY="test-secret-key-for-pytest-123456",
        USE_TZ=True,
        ALLOWED_HOSTS=["*"],
        ROOT_URLCONF=URLConf,
    )
    django.setup()

    # Create database tables
    call_command("migrate", "--run-syncdb", verbosity=0)
