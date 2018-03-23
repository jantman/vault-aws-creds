#!/usr/bin/env python
"""
Script to use STS Temporary Credentials from environment variables to generate
an AWS Console login URL.

Canonical source of latest version:
<https://github.com/jantman/vault-aws-creds/blob/master/aws-sts-console-url.py>

For further information, see also:
https://docs.aws.amazon.com/IAM/latest/UserGuide/
id_roles_providers_enable-console-custom-url.html

Installation
------------

Make this script executable and copy or symlink it somewhere on your PATH.

Usage
-----

``aws-sts-console-url.py``

License
-------

Free for any use provided that changes and improvements are sent back to me.

Changelog
---------

(be sure to increment __version__ with Changelog additions!!)

0.2.7 2018-02-25 Jason Antman <jason@jasonantman.com>:
- change to vault-aws-creds.py

0.2.6 2018-02-25 Jason Antman <jason@jasonantman.com>:
- change to vault-aws-creds.py

0.2.5 2018-02-20 Jason Antman <jason@jasonantman.com>:
- change to vault-aws-creds.py

0.2.4 2018-01-29 Jason Antman <jason@jasonantman.com>:
- change to vault-aws-creds.py

0.2.3 2018-01-03 Jason Antman <jason@jasonantman.com>:
- Initial version (versioned in sync with vault-aws-creds.py)
"""

import sys
import os
import argparse
import logging
import json

if sys.version_info[0] == 2:
    from httplib import HTTPSConnection, HTTPConnection
    import ConfigParser
    from urlparse import urlparse
    from urllib import quote_plus
else:
    from http.client import HTTPSConnection, HTTPConnection
    import configparser as ConfigParser
    from urllib.parse import urlparse, quote_plus

__version__ = '0.2.7'  # increment version in other scripts in sync with this
__author__ = 'jason@jasonantman.com'
_SRC_URL = 'https://github.com/jantman/vault-aws-creds/blob/master/' \
           'aws-sts-console-url.py'

DEFAULT_REGION = 'us-east-1'

FORMAT = "[%(asctime)s %(levelname)s] %(message)s"
logging.basicConfig(level=logging.WARNING, format=FORMAT)
logger = logging.getLogger()


class StsUrlGenerator(object):

    def __init__(self):
        self.creds = self._get_creds_from_env()

    def _get_creds_from_env(self):
        """
        Get AWS credentials from environment variables.

        :return: dict of AWS credentials, suitable for passing to the
        https://signin.aws.amazon.com/federation API.
        :rtype: dict
        """
        res = {}
        logger.debug('Getting AWS credentials from environment')
        for varname, key in {
            'AWS_ACCESS_KEY_ID': 'sessionId',
            'AWS_SECRET_ACCESS_KEY': 'sessionKey',
            'AWS_SESSION_TOKEN': 'sessionToken'
        }.items():
            if varname not in os.environ:
                raise RuntimeError(
                    'ERROR: %s environment variable must be set to use this '
                    'script.' % varname
                )
            res[key] = os.environ[varname]
        logger.info('Got AWS credentials from environment variables')
        return res

    def generate(self):
        """
        Generate an STS login URL, and print it to STDOUT.
        """
        signin_token = self._get_signin_token(self.creds)
        logger.debug('Ok, got valid signin token.')
        url = 'https://signin.aws.amazon.com/federation' \
              '?Action=login' \
              '&Issuer=%s' \
              '&Destination=%s' \
              '&SigninToken=%s' % (
            quote_plus(_SRC_URL),
            quote_plus('https://console.aws.amazon.com/'),
            signin_token
        )
        sys.stderr.write(
            'The following sign-in URL must be used within 15 minutes:\n'
        )
        print(url)


    def _get_signin_token(self, creds):
        """
        GET the generated Signin Token from the federation endpoint

        :param creds: credentials to pass to the federation endpoint
        :type creds: dict
        :return: signin token returned by the federation endpoint
        :rtype: str
        """
        host = 'signin.aws.amazon.com'
        req_path = 'https://signin.aws.amazon.com/federation' \
                   '?Action=getSigninToken' \
                   '&Session=%s' % quote_plus(json.dumps(creds))
        logger.debug('HTTPS GET request to %s: %s', host, req_path)
        conn = HTTPSConnection(host, 443)
        conn.request('GET', req_path)
        resp = conn.getresponse()
        logger.debug('Response: HTTP %s %s', resp.status, resp.reason)
        logger.debug('Headers: %s', resp.getheaders())
        body = resp.read()
        logger.debug('Body: %s', body.strip())
        if resp.status != 200:
            logger.critical('AWS Federation endpoint responded HTTP %s %s: %s',
                            resp.status, resp.reason, body)
            raise RuntimeError('Error obtaining console signin credentials.')
        try:
            b = json.loads(body)['SigninToken']
        except Exception:
            logger.critical(
                'AWS Federation endpoint returned an invalid response: %s',
                body
            )
            raise RuntimeError('Invalid response from AWS Federation endpoint.')
        return b


def set_log_info():
    """set logger level to INFO"""
    set_log_level_format(logging.INFO,
                         '%(asctime)s %(levelname)s:%(name)s:%(message)s')


def set_log_debug():
    """set logger level to DEBUG, and debug-level output format"""
    set_log_level_format(
        logging.DEBUG,
        "%(asctime)s [%(levelname)s %(filename)s:%(lineno)s - "
        "%(name)s.%(funcName)s() ] %(message)s"
    )


def set_log_level_format(level, format):
    """
    Set logger level and format.

    :param level: logging level; see the :py:mod:`logging` constants.
    :type level: int
    :param format: logging formatter format string
    :type format: str
    """
    formatter = logging.Formatter(fmt=format)
    logger.handlers[0].setFormatter(formatter)
    logger.setLevel(level)


def parse_args(argv):
    """
    Parse command line arguments
    :param argv: command line arguments, not including script name
      (i.e. ``sys.argv[1:]``)
    :type argv: list
    :return: parsed command line arguments
    :rtype: argparse.Namespace
    """
    p = argparse.ArgumentParser(
        description='Generate and print to STDOUT an AWS Console login URL, '
                    'based on STS temporary credentials in environment '
                    'variables.'
    )
    p.add_argument('-v', '--verbose', dest='verbose', action='count', default=0,
                   help='verbose output. specify twice for debug-level output.')
    p.add_argument('-V', '--version', action='store_true', default=False,
                   help='Print version number and exit', dest='version')
    args = p.parse_args(argv)
    if args.version:
        sys.stderr.write(
            "aws-sts-console-url.py version %s <%s>\n" % (
                __version__, _SRC_URL
            )
        )
        raise SystemExit(1)
    return args

if __name__ == "__main__":
    args = parse_args(sys.argv[1:])

    # set logging level
    if args.verbose > 1:
        set_log_debug()
    elif args.verbose == 1:
        set_log_info()

    StsUrlGenerator().generate()
