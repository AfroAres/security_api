import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Configuración de seguridad
SECRET_KEY = os.getenv('DJANGO_SECRET_KEY', 'reemplaza_con_tu_clave_secreta')
DEBUG = os.getenv('DJANGO_DEBUG', 'True') == 'True'

ALLOWED_HOSTS = ['educativaipchile.cl', 'localhost', '127.0.0.1']

INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.staticfiles',
    'rest_framework',  # Agregar Django REST Framework
    'api',  # Tu aplicación específica
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
]

ROOT_URLCONF = 'security_api.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
            ],
        },
    },
]

WSGI_APPLICATION = 'security_api.wsgi.application'

# Deshabilitar base de datos
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.dummy',  # Motor ficticio
    }
}

AUTH_PASSWORD_VALIDATORS = []  # Sin validadores de contraseñas ya que no se usará autenticación

LANGUAGE_CODE = 'es-es'

TIME_ZONE = 'America/Santiago'  # Ajustado para tu ubicación en Chile

USE_I18N = True
USE_L10N = True
USE_TZ = True

STATIC_URL = '/static/'
