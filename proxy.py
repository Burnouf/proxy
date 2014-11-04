#!/usr/bin/env python

import re, httplib, base64, sys, binascii
import cherryproxy

def is_SSH_req(string):
   if string == None:
      return False
   try :
       if 'OpenSSH_' in base64.b64decode(string):
         return True
   except:
       pass
   try :
        if 'OpenSSH_' in base64.b32decode(string):
            return True
   except:
       pass
   try :
        if 'OpenSSH_' in base64.b16decode(string):
            return True
   except:
       pass
   try :
        if 'OpenSSH_' in binascii.a2b_uu(string):
            return True
   except:
       pass
   try :
       if 'OpenSSH_' in binascii.a2b_base64(string):
            return True
   except:
       pass
   try :
       if 'OpenSSH_' in binascii.a2b_qp(string):
            return True
   except:
       pass
   try :
       if 'OpenSSH_' in binascii.a2b_hqx(string):
            return True
   except:
       pass
   try :
       if 'OpenSSH_' in binascii.a2b_hex(string):
            return True
   except:
       pass
   try :
       if 'OpenSSH_' in string:
            return True
   except:
       pass
   return False

class Proxy(cherryproxy.CherryProxy):
   def denie(self):
      self.set_response_forbidden(reason="how about no?")

   def filter_request(self):
      global __proxy__
      if is_SSH_req(self.req.data):
         print "Ai-je bien lu 'SSH' ?"
         self.denie()

   def filter_request_headers(self):
      accepted = True
      headers = self.req.headers.keys()
      if not ('user-agent' in headers):
         print "User-Agent vide ou incorrect !"
         accepted = False
      if not re.match('.*(\:[80|443])?', self.req.netloc):
         print "Je suis un proxy web ! Tu m'entends ? WEB !"
         accepted = False
      if is_SSH_req(self.req.query):
         print "Ai-je bien lu 'SSH' ?"
         accepted = False
      if not accepted:
         self.denie()

   def filter_response(self):
      headers = dict(self.resp.headers)
      if 'content-encoding' in headers.keys():
         if not headers['content-encoding'] in self.req.headers['accept-encoding'].split(','):
            print "Tu sais quoi ? Ton serveur t'as repondu de la merde !"
            self.denie()

cherryproxy.main(Proxy)

