#!/usr/bin/env python
# -*- coding: latin-1 -*-

import argparse
import ConfigParser
import cookielib
import logging
import os
import re
import shlex
import stat
import subprocess
import sys
import urllib
import urllib2
import urlparse


## Order of the required arguments per page/tuple
AUTH_KEYS = [ ('username', 'realm'), ('password',), ('user#2', 'password#2') ]

## How do I know I have a hung session? Search for this string
HUNG_SESSION_KEY = 'btnContinue'

## Ugly, but venerable RE's to get the form data
FORM_KEY = re.compile("""\<input\ type\="hidden"\ name\=\"(\S+)\"\ value\=\"(\S+)\"\>""", re.VERBOSE)
FORM_URI = re.compile("""\<form\ .*?\ action\=\"(?P<Uri>\S+)\" """, re.VERBOSE)


class JuniperVPN:
    """A script to help with Juniper VPN connections on 64-bit linux.
    
    The JuniperVPN java client works sufficiently well on 32-bit linux, and
    even somewhat well on 64-bit linux with the aid of The Mad Scientists' 
    junipernc script.  (http://mad-scientist.net/junipernc)  However, if you are
    unfortunate enough that your company has implemented a two-factor form
    of authentication, your login process becomes sufficiently complicated to
    the point where some might not bother.
    
    As prerequistes for executing this script, it is required that the Juniper
    software has been downloaded to your computer.  (See 
    http://mad-scientist.us/juniper.html for instructions.)  Next, leveraging
    the work of sdeming, you will need to create an 'ncui' executable from the
    ncui.so, and additionally retrieve the SSL certificate from your 
    companies' website.  The instructions are available here:
    http://makefile.com/.plan/2009/10/27/juniper-vpn-64-bit-linux-an-unsolved-mystery
    Once those steps are complete, this script will automatically log you in,
    retrieve the DSID cookie, and call the 'ncui' executable.  
    
    The first time the script is executed, you will want to use the '-c'
    option to create a new configuration file.
    
    Note:
    
        This script assumes many things about the method for logging in.  
        Please see the login() method if you need to tweak anything.

    Additions:
      - Some implemntations have multiple pages that require sundry auth data. For example
        the username & realm on the first page, the pin on the next, etc...
        Added the ability to cycle through each page providing the respective auth data. This
        is configured by the AUTH_KEYS variable above. Just look at the source of each page
        (in order) and grab the names of the needed input variables in the form. Provide them 
        as a tuple of the AUTH_KEYS variable, and the script will use them. Page #1 is tuple[0],
        page 2 is tuple[1], etc..

      - In the course of a day, your connection may get..well.. disconnected. The ncui does not
        gracefully exit connections, so you would have to authenticate with a web browser 
        and gracefully exit your session before using the script again. Since the DSID is still
        good, unless the server disconnects you for a timeout, bad behavior, stinky feet, etc..,
        thus the session can be re-established without another authentication. An option is now
        presented to allow the connection to be re-used if you know you have one. If you don't 
        know whether you have one or not, just authenticate normally and if there is a hung session
        the script will use that session instead of creating another.
    
    """

    def __init__(self):
        # Configuration file
        self.config      = os.path.expanduser("~/.junipervpn")
        self.lastDsid    = os.path.expanduser("~/.junipervpn_ID")
        self.section     = "junipervpn"
        self.hungSession = False
        
        # log file
        self.logFile = "~/.junipervpn.log"
        logging.basicConfig(filename=os.path.expanduser(self.logFile),
                            level=logging.DEBUG,
                            filemode="w")
        logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', 
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        
        # Configuration options
        parser = argparse.ArgumentParser(description='64-bit Linux Juniper VPN two-factor authentication automation.')
        parser.add_argument("-c", "--create", action="store_true", 
                            help='create a new config file.')
        args = parser.parse_args()
        create = vars(args)["create"]        

        # If we're commanded to create a new config file, remove one that may exist
        if(create==True):
            logging.debug("Creation of new configuration file requested.")
            self.removeConfig()
            self.createConfig()
            sys.exit()

        # Now create & read
        if (os.path.exists(self.config)):
            self.readConfig()
        else:
            sys.exit("Configuration file ('%s') not found." % self.config)

        # Verify these files exist
        if (os.path.isfile(os.path.expanduser(self.ncui)) == False):
            logging.debug("ncui exec ('%s') not found." % self.ncui)
            sys.exit("Unable to find ncui executable.")
        if (os.path.isfile(os.path.expanduser(self.cert)) == False):
            logging.debug("ssl cert ('%s') not found." % self.cert)
            sys.exit("Unable to find SSL certificate.")

        # Prepare the cookie jar for the vpn website.
        self.cj     = cookielib.CookieJar()
        self.Opener = urllib2.build_opener( urllib2.HTTPSHandler(), urllib2.HTTPCookieProcessor(self.cj) )
        self.host   = urlparse.urlparse(self.url).netloc

    def getUserInfo(self):
        """Prompts the user for their token and optionally their password."""
        ## If I know I have a dormant session, just use that
        if raw_input('Want To Try Using Your Old Session (y)') == 'y' : 
          self.doLogin = False
          return
        else : 
          self.doLogin = True
        print "Preparing to login."
        # If you didn't fill in the password, it'll prompt for that.
        if self.password == "" : self.password = raw_input("Password:  ")
        # Now it will prompt the user for the SecurID token
        self.pintoken = self.pin + raw_input("Token:  ")

        ## Create a dict of auth data so we can configure all of the options in the script head
        self.AuthData = {
          'username'    : self.username,
          'realm'       : self.realm,
          'password'    : self.pintoken,
          'user#2'      : self.username, 
          'password#2'  : self.password,
        }


    def login(self):
        """Attempts to navigate through the multitude of pages to login"""
        ## Open the first page to get'r started
        try:
          Page = self.Opener.open( self.url ).read()
        except ValueError:
          logging.debug("Invalid Start URL: ('%s')" % self.url )
          sys.exit("Invalid Start URL: '%s'" % Url )

        ## Unpack the authKeys (which navigate us through the pages) 
        for Items in AUTH_KEYS:

          ## Grab the next URL
          Match = re.search( FORM_URI, Page )
          if not Match :
            logging.debug("Unable to grab the URI from the form in ('%s'). Better check the regExp" % Url )
            sys.exit("No URI Found In Form at URL: '%s'" % Url )

          AuthD = {}
          ## Add any hidden keys that the form requires as we lament the stateless nature of http....(sigh)..
          for (Key, Val) in re.findall( FORM_KEY, Page ) : AuthD[ Key ] = Val

          ## Put together the authData for this page
          for Key in Items : AuthD[ Key ] = self.AuthData[ Key ]

          ## Using the UrlJoin we'll fashion the next URL
          Url = urlparse.urljoin( self.url, Match.groupdict()['Uri'] )

          ## Encode the Args ( there won't be any for the intro pageOpen the page and send the data
          try:
            Page = self.Opener.open( Url, urllib.urlencode( AuthD ) ).read()
          except ValueError:
            logging.debug("Unable to perform login. Invalid url: ('%s')" % Url )
            sys.exit("Invalid URL: '%s'" % Url )

          ## Check for hung sessions
          if Page.find( HUNG_SESSION_KEY ) > -1 : self.hungSession = True


    def getDSIDValue(self):
        """Retrieves the value of the DSID cookie."""
        for c in self.cj:
            if c.name == "DSID":
                logging.debug("Successfully retrieved DSID cookie: ('%s')" % c.value)
                return c.value
        logging.debug("Login to '%s' failed; no DSID cookie found." % self.url)
        sys.exit("Login failed, no DSID cookie found.")

    def startVPN(self):
        """Calls the executable with the appropriate options."""
        ## Hung session? Use the last known DSID
        if self.hungSession or not self.doLogin: 
          DSID = open( self.lastDsid ).read()
        else                : 
          DSID = self.getDSIDValue()
          open( self.lastDsid, 'wb' ).write( DSID )

        cmd = '%s -h %s -c DSID=%s -f %s' % (os.path.expanduser(self.ncui),
                                             self.host,
                                             DSID,
                                             os.path.expanduser(self.cert))
        print "Starting VPN connection..."
        logging.debug("Calling ncui exec with: %s" % cmd)
        cmd = shlex.split(cmd)
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
        # When launched, there will be a prompt for a Password.  
        self.p.communicate("\n")
        print "VPN connection started."
        
    def createConfig(self):
        """Creates a configuration file if none is found."""
        print "Creating new configuration file."
        logging.debug("Creating new config file: ('%s')" % self.config)
        # Prompt for input
        user = raw_input("Username:  ")
        pin  = raw_input("PIN:  ")
        store = raw_input("Store Password? (Y|n):  ").strip().lower()
        if (store == "" or store == "y"):
            # Only prompt for the password if they've elected to store it
            passwd = raw_input("Password:  ").strip()
        else:
            passwd = None
            
        # defaults for the program / certificate
        ncuiDefault = "~/.juniper_networks/network_connect/ncui"
        certDefault = "~/.juniper_networks/network_connect/ssl.crt"
        prompt = "ncui:  (%s):  " % ncuiDefault
        ncui = raw_input(prompt).strip()
        if (ncui == ""):
            ncui = ncuiDefault
        prompt = "cert:  (%s):  " % certDefault
        cert = raw_input(prompt).strip()
        if (cert == ""):
            cert = certDefault
            
        # The URl of the page you'd login to
        url    = raw_input("Login Page URL (Paste the URL from your browser at the first login page here): ").strip()
        realm  = raw_input("Realm: ").strip()
            
        # Create the config object    
        config = ConfigParser.RawConfigParser()
        config.add_section(self.section)
        config.set(self.section, "username", user)
        if passwd != None:
            config.set(self.section, "passwd", passwd)
        else:
            config.set(self.section, "passwd", "")
        config.set(self.section, "pin", pin)
        config.set(self.section, "ncui", ncui)
        config.set(self.section, "cert", cert)
        config.set(self.section, "url", url)
        config.set(self.section, "realm", realm)
        
        # Write out the config file
        with open(self.config, 'wb') as configfile:
            config.write(configfile)
        logging.debug("Successfully wrote configuration file.")
        # As this config file contains personal info, chmod 600 it.
        os.chmod(self.config, stat.S_IRUSR | stat.S_IWUSR)    
        
        print "Config file written to %s!\n" % self.config  
            
    def readConfig(self):
        """Reads in the config file and sets the instance vars."""
        logging.debug("Reading configuration file.")
        config = ConfigParser.RawConfigParser()
        config.read(self.config)
        self.username = config.get(self.section, "username")
        self.pin = config.get(self.section, "pin")
        self.password = config.get(self.section, "passwd")
        self.ncui = config.get(self.section, "ncui")
        self.cert = config.get(self.section, "cert")
        self.url = config.get(self.section, "url")  
        self.realm = config.get(self.section, "realm")
        
    def removeConfig(self):
        """Attempts to remove a pre-existing config file."""
        if(os.path.exists(self.config)):
            logging.debug("Removing configuration file.")
            os.remove(self.config)
        else:
            logging.debug("Configuration file doesn't exist, cannot remove.")
    
    def stopVPN(self):
        """Stops the VPN connection."""
        print "\nStopping VPN connection..."
        try:
            self.p.terminate()
        except:
            print "NCUI process wasn't running."

    def run(self):
        """Handles the thread of execution."""
        self.getUserInfo()
        if self.doLogin : self.login()
        self.startVPN()

    def stop(self):
        """Ends the vpn session."""
        self.stopVPN()

if __name__ == "__main__":
    vpn = JuniperVPN()
    try:
        vpn.run()
    except KeyboardInterrupt:
        vpn.stop()
