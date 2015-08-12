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

from django.shortcuts import render
from django.http import Http404
from django.http import HttpResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from models import *
from utils import *
import traceback
import time
import logging
logger = logging.getLogger("ntbserver")
from pymongo.errors import AutoReconnect

@csrf_exempt
def subscribe_view(request):
    """
        Request ( POST ) :
            machine id
            public key in base64
            signature of machine id with the private key
        Response :
            OK  : 200 -> empty page
            BAD : 400 -> empty page
    """
    ip=get_client_ip(request)
    logger.debug("%s Subscription request" %(ip))
    try :
        if request.method == 'POST':
            logger.debug("%s Subscription POST request " %(ip))
            if set(['id', 'public_key', 'signature']).issubset(set(request.POST.keys())):
                rid=request.POST.get('id')
                rpublic_key=request.POST.get('public_key')
                rsignature=request.POST.get('signature')
                logger.debug("%s Subscription id : %s" %(ip, rid))
                # See settings.MAX_AUTO_RECONNECT_ATTEMPTS comment
                for attempt in xrange(settings.MAX_AUTO_RECONNECT_ATTEMPTS):
                    try:
                        m = Machine.objects.filter(machine_id=rid)
                        if not m:
                            logger.debug("%s Subscription no machine found for : %s" %(ip, rid))
                            m = Machine(machine_id=rid, public_key=rpublic_key, passphrase='')
                            if m.verify_sign(rsignature) :
                                logger.debug("%s Signature OK ( %s )" %(ip, rid))
                                m.generate_passphrase()
                                m.save()
                                logger.info("%s Subscription OK ( %s )" %(ip, rid))
                                Logs(action='subscribe' , ip=ip, machine = m, result = True).save()
                                return HttpResponse('')
                            else :
                                logger.error("%s Subscription ERROR : bad signature ( %s )" %(ip, rid ))
                        else :
                            logger.error("%s Subscription ERROR : id already exist ( %s )" %(ip, rid ))
                            for ms in m:
                                if ms.disabled :
                                    logger.error("%s Subscription ALERT : DISABLES ID ( %s )" %(ip, rid ))
                                Logs(action='subscribe' , ip=ip, machine = ms).save()
                            return HttpResponseBadRequest('')
                    except AutoReconnect as e:
                        wait_t = 0.5 * pow(2, attempt) # exponential back off
                        logger.warning("PyMongo auto-reconnecting... %s. Waiting %.1f seconds. (Attempt %i)" %( str(e), wait_t, attempt ))
                        if attempt >= settings.MAX_AUTO_RECONNECT_ATTEMPTS:
                            logger.error("PyMongo MAX ATTEMPTS REACHED ... %s (Attempt %i)" %( str(e), attempt ))
                            raise
                        time.sleep(wait_t)
            else :
                logger.error("%s Subscription ERROR : bad request parameters" %(ip))
        else :
            logger.error("%s Subscription ERROR : Not POST request" %(ip))
        Logs(action='subscribe' , ip=ip).save()
        return HttpResponseBadRequest('')
    except Exception, e:
        logger.error("%s Passphrase ERROR : ( %s ) %s" %(ip, type(e).__name__ , str(e) ))
        print(traceback.format_exc())
        return HttpResponseBadRequest('')

@csrf_exempt
def passphrase_view(request):
    """
        Request ( POST ) :
            machine id
            signature of machine id with the private key
        Response :
            OK  : 200 -> encripted passphrase whit the public key
            BAD : 400 -> empty page
    """
    ip=get_client_ip(request)
    logger.debug("%s Passphrase request" %(ip))
    try:
        if request.method == 'POST':
            logger.debug("%s Passphrase POST request " %(ip))
            if set(['id', 'signature']).issubset(set(request.POST.keys())):
                rid=request.POST.get('id')
                rsignature=request.POST.get('signature')
                logger.debug("%s Passphrase id : %s" %(ip, rid))
                # See settings.MAX_AUTO_RECONNECT_ATTEMPTS comment
                for attempt in xrange(settings.MAX_AUTO_RECONNECT_ATTEMPTS):
                    try:
                        m = Machine.objects.filter(machine_id=rid)
                        if m and len(m) == 1:
                            logger.debug("%s Passphrase one machine found for : %s" %(ip,rid))
                            if not m[0].disabled :
                                if m[0].verify_sign(rsignature):
                                    logger.info("%s Passphrase OK ( %s )" %(ip, rid))
                                    Logs(action='passphrase' , ip=ip, machine = m[0], result = True).save()
                                    return HttpResponse(m[0].verify_prepare_passphrase(), content_type='text/plain')
                                else :
                                    logger.debug("%s Passphrase ERROR : bad signature ( %s )" %(ip, rid))
                                    Logs(action='passphrase' , ip=ip, machine = m[0]).save()
                                    return HttpResponseBadRequest('')
                            else:
                                logger.debug("%s Passphrase ALERT : DISABLED ID ( %s )" %(ip, rid))
                                Logs(action='passphrase' , ip=ip, machine = m[0]).save()
                                return HttpResponseBadRequest('')
                        elif m :
                            logger.error("%s Passphrase ERROR : id not unique ( %s )" %(ip, rid ))
                            for ms in m:
                                Logs(action='passphrase' , ip=ip, machine = ms).save()
                            return HttpResponseBadRequest('')
                        else :
                            logger.error("%s Passphrase ERROR : id not exist ( %s )" %(ip, rid ))
                    except AutoReconnect as e:
                        wait_t = 0.5 * pow(2, attempt) # exponential back off
                        logger.warning("PyMongo auto-reconnecting... %s. Waiting %.1f seconds. (Attempt %i)" %( str(e), wait_t, attempt ))
                        if attempt >= settings.MAX_AUTO_RECONNECT_ATTEMPTS:
                            logger.error("PyMongo MAX ATTEMPTS REACHED ... %s (Attempt %i)" %( str(e), attempt ))
                            raise
                        time.sleep(wait_t)
            else :
                logger.error("%s Passphrase ERROR : bad request parameters" %(ip))
        else :
            logger.error("%s Passphrase ERROR : Not POST request" %(ip))
        Logs(action='passphrase' , ip=get_client_ip(request)).save()
        return HttpResponseBadRequest('')
    except Exception, e:
        logger.error("%s Passphrase ERROR : ( %s ) %s" %(ip, type(e).__name__ , str(e) ))
        print(traceback.format_exc())
        return HttpResponseBadRequest('')
