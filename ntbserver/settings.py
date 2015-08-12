# -*- coding: utf8 -*-

# Copyright GREYC - UMR 6072 ; Université de Caen Normandie
# Esplanade de la paix
# CS 14032
# 14032 Caen CEDEX 5
# contributeur : Pierre BLONDEAU, Davy GIGAN, Cyprien GOTTSTEIN (2014)
#
# Pierre BLONDEAU - pierre.blondeau@unicaen.fr
# Davy GIGAN - davy.gigan@unicaen.fr
# Cyprien GOTTSTEIN - gottstein.cyprien@gmail.com
#
# Ce logiciel est un programme informatique servant à déchiffrer un linux
# par le réseau et sans intervention de l'utilisateur.
#
# Ce logiciel est régi par la licence CeCILL-B soumise au droit français et
# respectant les principes de diffusion des logiciels libres. Vous pouvez
# utiliser, modifier et/ou redistribuer ce programme sous les conditions
# de la licence CeCILL-B telle que diffusée par le CEA, le CNRS et l'INRIA
# sur le site "http://www.cecill.info".
#
# En contrepartie de l'accessibilité au code source et des droits de copie,
# de modification et de redistribution accordés par cette licence, il n'est
# offert aux utilisateurs qu'une garantie limitée.  Pour les mêmes raisons,
# seule une responsabilité restreinte pèse sur l'auteur du programme,  le
# titulaire des droits patrimoniaux et les concédants successifs.
#
# A cet égard  l'attention de l'utilisateur est attirée sur les risques
# associés au chargement,  à l'utilisation,  à la modification et/ou au
# développement et à la reproduction du logiciel par l'utilisateur étant
# donné sa spécificité de logiciel libre, qui peut le rendre complexe à
# manipuler et qui le réserve donc à des développeurs et des professionnels
# avertis possédant  des  connaissances  informatiques approfondies.  Les
# utilisateurs sont donc invités à charger  et  tester  l'adéquation  du
# logiciel à leurs besoins dans des conditions permettant d'assurer la
# sécurité de leurs systèmes et ou de leurs données et, plus généralement,
# à l'utiliser et l'exploiter dans les mêmes conditions de sécurité.
#
# Le fait que vous puissiez accéder à cet en-tête signifie que vous avez
# pris connaissance de la licence CeCILL-B, et que vous en avez accepté les
# termes.
#
# ================================ English ================================
#
# Copyright GREYC - UMR 6072 ; Université de Caen Normandie
# Esplanade de la paix
# CS 14032
# 14032 Caen CEDEX 5
# contributor(s) : Pierre BLONDEAU, Davy GIGAN, Cyprien GOTTSTEIN (2014)
#
# Pierre BLONDEAU - pierre.blondeau@unicaen.fr
# Davy GIGAN - davy.gigan@unicaen.fr
# Cyprien GOTTSTEIN - gottstein.cyprien@gmail.com
#
# This software is a computer program whose purpose is to decrypt a linux
# by the network without user intervention.
#
# This software is governed by the CeCILL-B license under French law and
# abiding by the rules of distribution of free software.  You can  use,
# modify and/ or redistribute the software under the terms of the CeCILL-B
# license as circulated by CEA, CNRS and INRIA at the following URL
# "http://www.cecill.info".
#
# As a counterpart to the access to the source code and  rights to copy,
# modify and redistribute granted by the license, users are provided only
# with a limited warranty  and the software's author,  the holder of the
# economic rights,  and the successive licensors  have only  limited
# liability.
#
# In this respect, the user's attention is drawn to the risks associated
# with loading,  using,  modifying and/or developing or reproducing the
# software by the user in light of its specific status of free software,
# that may mean  that it is complicated to manipulate,  and  that  also
# therefore means  that it is reserved for developers  and  experienced
# professionals having in-depth computer knowledge. Users are therefore
# encouraged to load and test the software's suitability as regards their
# requirements in conditions enabling the security of their systems and/or
# data to be ensured and,  more generally, to use and operate it in the
# same conditions as regards security.
#
# The fact that you are presently reading this means that you have had
# knowledge of the CeCILL-B license and that you accept its terms.

"""
Django settings for ntbserver project.
"""

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
import os
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
import logging, socket, mongoengine

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.7/howto/deployment/checklist/

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = None
TEMPLATE_DEBUG = None

ALLOWED_HOSTS = []

# Application definition

INSTALLED_APPS = (
    # 'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'ntbserver_api',
)

MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
)

ROOT_URLCONF = 'ntbserver.urls'

WSGI_APPLICATION = 'ntbserver.wsgi.application'

# Internationalization
# https://docs.djangoproject.com/en/1.7/topics/i18n/
LANGUAGE_CODE = 'en'
USE_I18N = True
USE_L10N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.7/howto/static-files/
STATIC_URL = '/static/'

SESSION_SERIALIZER = 'django.contrib.sessions.serializers.JSONSerializer'
SESSION_ENGINE = 'mongoengine.django.sessions'

AUTHENTICATION_BACKENDS = (
    'mongoengine.django.auth.MongoEngineBackend',
)

DATABASES = {
    'default': {
        'ENGINE': '',
    },
}

try:
    HOSTNAME = socket.gethostname()
except:
    HOSTNAME = 'localhost'

SECRET_KEY = None
LOG_LEVEL = 'INFO'

# http://api.mongodb.org/python/current/api/pymongo/errors.html#pymongo.errors.AutoReconnect
# The application need to manage itself the lost of the primary.
# http://emptysqua.re/blog/save-the-monkey-reliably-writing-to-mongodb/
# https://gist.github.com/anthonywu/1696591
# Other solutions ? : https://github.com/arngarden/MongoDBProxy
MAX_AUTO_RECONNECT_ATTEMPTS = 5

try:
    from local_settings import *
except ImportError:
    logging.warning("No local_settings file found.")

from logging.handlers import SysLogHandler
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format' : '%(asctime)s ' + HOSTNAME + ' %(name)s: %(message)s',
            'datefmt' : '%b %d %H:%M:%S',
        },
    },
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.handlers.WatchedFileHandler',
            'filename': '/var/log/ntbserver/ntbserver.log',
            'formatter': 'verbose'
        },
        # 'mail_admins': {
        #     'level': 'ERROR',
        #     'filters': ['require_debug_false'],
        #     'class': 'django.utils.log.AdminEmailHandler'
        # },
    },
    'loggers': {
        'ntbserver': {
            # 'handlers': ['file', 'mail_admins'],
            'handlers': ['file'],
            'propagate': True,
            'level': LOG_LEVEL,
        },
    }
}

logger=logging.getLogger("ntbserver")

if not SECRET_KEY:
    SECRET_FILE = os.path.join(os.path.dirname(__file__), 'secret.txt')
    try:
        SECRET_KEY = open(SECRET_FILE).read().strip()
    except IOError:
        import random, string
        SECRET_KEY = ''.join([random.SystemRandom().choice(string.digits + string.letters + string.punctuation) for i in range(100)])
        logger.warning("No secret file found (%s). Generate temporary SECRET_KEY" %(SECRET_FILE))
