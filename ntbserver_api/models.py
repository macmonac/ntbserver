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

from mongoengine import *
import os
import datetime
from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_v1_5_Cipher
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_Signature
from Crypto.Hash import SHA256
from base64 import b64encode, b64decode


class Machine(Document):
    machine_id = StringField(unique=True, required=True, max_length=255)
    public_key = StringField(required=True)
    passphrase = StringField()
    disabled = BooleanField(required=True, default=False)
    disabled_date = DateTimeField()
    prepared_passphrase = StringField()
    prepared_passphrase_date = DateTimeField()
    meta = {'indexes': [{'fields': ['machine_id'], 'unique': True}]}

    def __unicode__(self):
        return self.machine_id

    def save(self, *args, **kwargs):
        if not self.disabled and not self.prepared_passphrase and self.passphrase:
            self.prepare_passphrase()
        return super(Machine, self).save(*args, **kwargs)

    def generate_passphrase(self):
        self.passphrase = b64encode(os.urandom(500))

    def prepare_passphrase(self):
        if self.passphrase:
            rsakey = RSA.importKey(self.public_key)
            # Cypher choice : https://www.openssl.org/docs/crypto/RSA_public_encrypt.html
            # Need server/client update to use OAEP
            # cipher = PKCS1_OAEP.new(rsakey)
            cipher = PKCS1_v1_5_Cipher.new(rsakey)
            # https://www.dlitz.net/software/pycrypto/api/2.6/Crypto.Cipher.PKCS1_v1_5.PKCS115_Cipher-class.html#encrypt
            self.prepared_passphrase = b64encode(cipher.encrypt(b64decode(self.passphrase)))
            self.prepared_passphrase_date = datetime.datetime.now()

    def verify_prepare_passphrase(self):
        if not self.prepared_passphrase or not self.prepared_passphrase_date or self.prepared_passphrase_date < datetime.datetime.now() - datetime.timedelta(minutes=30):
            self.prepare_passphrase()
            self.save()
        return self.prepared_passphrase

    def verify_sign(self, signature):
        rsakey = RSA.importKey(self.public_key)
        signer = PKCS1_v1_5_Signature.new(rsakey)
        digest = SHA256.new()
        digest.update(self.machine_id)
        return signer.verify(digest, b64decode(signature))

    def enable(self):
        self.disabled = False
        self.disabled_date = datetime.datetime.now()
        self.save()

    def disable(self):
        self.disabled = True
        self.disabled_date = datetime.datetime.now()
        self.save()


class Logs(Document):
    ip = StringField(required=True, max_length=255)
    action = StringField(required=True, max_length=255)
    result = BooleanField(required=True, default=False)
    date = DateTimeField()
    machine = ReferenceField(Machine)

    def __unicode__(self):
        return self.action

    def save(self, *args, **kwargs):
        if not self.date:
            self.date = datetime.datetime.now()
        return super(Logs, self).save(*args, **kwargs)


class Version(Document):
    version = IntField(required=True, default=3)

    def __unicode__(self):
        return self.version
