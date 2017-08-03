#!/home/jantman/venvs/foo/bin/python
"""
Script to export Vault-derived temporary AWS creds in the environment.

Canonical source of latest version:
<https://github.com/jantman/vault-aws-creds/blob/master/vault-aws-creds.py>

Installation
------------

Add a wrapper to your ``~/.bashrc`` to allow this script to set env vars in
the current shell. The proper wrapper function will be output by running
``vault-aws-creds.py --wrapper-func``.

Without such a wrapper, you'll need to manually pass this script's output
through your shell's evaluation function, i.e. ``eval vault-aws-creds.py <args>``

Usage
-----

see `vault-aws-creds.py -h`

Development
-----------

__IMPORTANT__:

- The only thing that should ever be printed to STDOUT is bash code to be
 evaluated by the shell (i.e. environment variable exports).
- All logging, errors, and warnings to the user must go to STDERR.
- Any critical exceptions should raise a VaultException with a helpful message.

License
-------

Free for any use provided that changes and improvements are sent back to me.

Changelog
---------

0.1.0 2017-08-01 Jason Antman <jason@jasonantman.com>:
- Initial version
"""

import sys
import os
import argparse
import logging
from textwrap import dedent
import json
import ConfigParser

try:
    # python2
    from httplib import HTTPSConnection, HTTPConnection
except ImportError:
    # python3
    from http.client import HTTPSConnection, HTTPConnection

try:
    # python2
    from urlparse import urlparse
except ImportError:
    # python3
    from urllib.parse import urlparse

__version__ = '0.1.0'
__author__ = 'jason@jasonantman.com'
_SRC_URL = 'https://github.com/jantman/vault-aws-creds/blob/master/' \
           'vault-aws-creds.py'

DEFAULT_REGION = 'us-east-1'

FORMAT = "[%(asctime)s %(levelname)s] %(message)s"
logging.basicConfig(level=logging.WARNING, format=FORMAT)
logger = logging.getLogger()


def humantime(int_seconds):
    """convert integer seconds to human time"""
    s = int_seconds
    res = ''
    day = 86400
    if s >= 86400:
        res += '{c}d '.format(c=int(s / day))
        s = s % 86400
    if s >= 3600:
        res += '{c}h '.format(c=int(s / 3600))
        s = s % 3600
    if s >= 60:
        res += '{c}m '.format(c=int(s / 60))
        s = s % 60
    if s > 0:
        res += '{c}s'.format(c=s)
    return res


def bold(s):
    return "\033[1m%s\033[0m" % s


def red(s):
    return "\033[31m%s\033[0m" % s


def green(s):
    return "\033[32m%s\033[0m" % s


class VaultException(Exception):

    pass


class VaultAwsCredExporter(object):

    def __init__(self, config_path, region=None):
        self._config_path = os.path.abspath(config_path)
        self._config = self._read_config(self._config_path)
        if region is None:
            region = self._get_conf('defaults', 'region_name')
        if region is None:
            region = DEFAULT_REGION
        self._region = region
        self._set_conf('defaults', 'region_name', region)
        self._cli_region = region
        self._v_addr, self._v_token = self._set_vault_creds()
        self._v_scheme, self._v_host, self._v_port = self._parse_vault_url(
            self._v_addr
        )
        logger.debug('VAULT_ADDR=%s; scheme=%s host=%s port=%d',
                     self._v_addr, self._v_scheme, self._v_host, self._v_port)
        self._test_vault_creds()

    def _read_config(self, conf_path):
        """
        Read in the config file. Return a SafeConfigParser.

        :param conf_path: conf file path
        :type conf_path: str
        :return: ConfigParser
        :rtype: ConfigParser.SafeConfigParser
        """
        conf = ConfigParser.SafeConfigParser()
        conf.add_section('roles')
        logger.debug('Attempting to read config from: %s', conf_path)
        conf.read(conf_path)
        return conf

    def _set_conf(self, section, option, value):
        """
        Set a config value and then write the config file to disk.

        :param section: config file section name
        :type section: str
        :param option: option name in section
        :type option: str
        :param value: value to set for the option
        :type value: str
        """
        if not self._config.has_section(section):
            self._config.add_section(section)
        logger.debug('_set_conf: section=%s option=%s value=%s',
                     section, option, value)
        self._config.set(section, option, value)
        with open(self._config_path, 'wb') as fh:
            logger.debug('Writing config to: %s', self._config_path)
            self._config.write(fh)

    def _get_conf(self, section, option):
        """
        Attempt to read a given value (section and option) from the config
        file. If it does not exist, return a default if defined, or otherwise
        None.

        :param section: section name in config file
        :type section: str
        :param option: option name in section
        :type option: str
        :return: value or None
        """
        if not self._config.has_section(section):
            logger.debug('Config does not have section: %s', section)
            return None
        try:
            return self._config.get(section, option)
        except Exception as ex:
            logger.debug('Exception getting config %s/%s: %s',
                         section, option, ex)
            return None

    def _get_conf_bool(self, section, option, default=False):
        v = self._get_conf(section, option)
        if v is None:
            return default
        if v == 'true':
            return True
        return False

    def _set_conf_bool(self, section, option, value):
        if value is True:
            self._set_conf(section, option, 'true')
            return
        self._set_conf(section, option, 'false')

    @property
    def bash_wrapper(self):
        """
        Return the string bash wrapper function to execute this command and
        evaluate the STDOUT.

        :return: bash wrapper function for this command
        :rtype: str
        """
        p = os.path.realpath(__file__)
        wrapper = "function vault-aws-creds() {\n" \
                  "    # generated by vault-aws-creds.py version %s\n" \
                  "    # <%s>\n" \
                  "    # This executes the script with the supplied " \
                  "arguments and then\n" \
                  "    # evaluates the STDOUT. It lets us export env vars in " \
                  "an existing session.\n" \
                  "    x=$(%s --called-from-wrapper \"$@\")\n" \
                  "    [[ \"$?\" == \"0\" ]] && eval \"$x\"\n" \
                  "}" % (__version__, _SRC_URL, p)
        return wrapper

    def _set_vault_creds(self):
        """
        Get the Vault address and token. Confirm the token is valid, or raise
        an error otherwise. Return the address and token.

        :returns: 2-tuple of (VAULT_ADDR, VAULT_TOKEN) if token is valid
        :rtype: tuple
        """
        addr = os.environ.get('VAULT_ADDR', None)
        tkn = os.environ.get('VAULT_TOKEN', None)
        if addr is None:
            raise VaultException('Vault address not found; you must export the '
                                 'VAULT_ADDR environment variable.')
        if tkn is not None:
            logger.debug(
                'Using Vault Token from VAULT_TOKEN environment variable'
            )
            return addr, tkn
        p = os.path.expanduser('~/.vault-token')
        if not os.path.exists(p):
            raise VaultException(
                'VAULT_TOKEN environment variable is not set and ~/.vault-token'
                ' does not exist. Please run "vault auth" to authenticate to '
                'Vault.'
            )
        logger.debug('Reading Vault token from: %s', p)
        with open(p, 'r') as fh:
            tkn = fh.read().strip()
        return addr, tkn

    def _parse_vault_url(self, addr):
        """
        Parse the VAULT_ADDR into host and port. Return a 2-tuple of them.

        :param addr: VAULT_ADDR
        :type addr: str
        :return: 3-tuple (str scheme, str host, int port)
        :rtype: tuple
        """
        p = urlparse(addr)
        nl = p.netloc
        if ':' not in nl:
            return p.scheme, nl, 8200  # 8200 is default Vault port
        host, port = nl.split(':')
        return p.scheme, host, int(port)

    def _vault_request(self, method, path, body=None, headers={}, redir=None):
        """
        Send an HTTPS request to Vault. Return the response.

        :param method: HTTP method
        :type method: str
        :param path: Vault API path
        :type path: str
        :param body: request body
        :type body: str
        :param headers: additional headers to add to request
        :type headers: dict
        :param redir: Vault redirect location
        :type redir: str
        :return: HTTP response
        :rtype: str
        """
        if redir is None:
            scheme = self._v_scheme
            host = self._v_host
            port = self._v_port
        else:
            scheme, host, port = self._parse_vault_url(redir)
        if 'X-Vault-Token' not in headers:
            headers['X-Vault-Token'] = self._v_token
        if scheme == 'https':
            kls = HTTPSConnection
        else:
            kls = HTTPConnection
        conn = kls(host, port)
        logger.debug('%s request to %s:%s - %s %s',
                     scheme, host, port, method, path)
        conn.request(method, path, body, headers)
        resp = conn.getresponse()
        logger.debug('Response: HTTP %s %s', resp.status, resp.reason)
        logger.debug('Headers: %s', resp.getheaders())
        loc = resp.getheader('location', None)
        if loc is not None and 300 <= resp.status < 400:
            logger.debug('Vault %s redirect to: %s', resp.status, loc)
            return self._vault_request(method, path, body, headers, loc)
        resp_body = resp.read()
        logger.debug('Body: %s', resp_body.strip())
        # test for auth failure
        try:
            b = json.loads(resp_body)
        except Exception:
            b = {}
        if 'errors' in b and len(b['errors']) > 0:
            if 'permission denied' in b['errors']:
                raise VaultException(
                    'Vault request got a "permission denied" error; your token'
                    ' is probably expired. Run "vault auth" to reauthenticate '
                    'to Vault.'
                )
            raise VaultException(
                "Vault request %s %s resulted in error(s): %s" % (
                    method, path, b['errors']
                )
            )
        return resp_body

    def _test_vault_creds(self):
        """
        Confirm that the Vault token is valid. Exit otherwise.
        """
        raw = self._vault_request('GET', '/v1/auth/token/lookup-self')
        res = json.loads(raw)
        logger.info('Vault token is authenticated as %s (accessor: %s)',
                    res['data'].get('display_name', 'unknown'),
                    res['data'].get('accessor', 'unknown'))

    def _get_aws_mountpoints(self):
        """
        Return a dict of account name to mountpoint for all AWS mounts in Vault.

        :return: account name to mountpoint
        :rtype: dict
        """
        try:
            res = json.loads(self._vault_request('GET', '/v1/sys/mounts'))
        except VaultException as ex:
            if 'permission denied' not in str(ex):
                raise
            logger.error(
                'ERROR: Your token does not have permission to list Vault '
                'mount points; you will have to obtain the AWS backend mount '
                'points for your accounts from your Vault administrator.'
            )
            return {}
        mpoints = {}
        for k, v in res.items():
            if not isinstance(v, type({})):
                continue
            if v.get('type', 'unknown') != 'aws':
                continue
            mpoints[k.strip('/')] = k
            if k.startswith('aws_'):
                mpoints[k.strip('/')[4:]] = k
        logger.debug('AWS Mountpoints: %s', mpoints)
        return mpoints

    def list_roles(self, mpoint):
        """
        List the available Vault roles for the specified account (in Vault).

        :param mpoint: account name to list roles for
        :type mpoint: str
        :return: roles that the current user has access to
        :rtype: list
        """
        try:
            res = json.loads(
                self._vault_request('LIST', '/v1/%sroles' % mpoint)
            )
        except VaultException as ex:
            if 'permission denied' not in str(ex):
                raise
            logger.error(
                'ERROR: Your token does not have permission to list available '
                'roles for the %s mount point; you will have to obtain your '
                'role name for this account from your Vault administrator.'
                '' % mpoint
            )
            return []
        roles = []
        for rname in res['data']['keys']:
            path = '%ssts/%s' % (mpoint, rname)
            logger.debug('Checking capabilities for: %s', path)
            caps = json.loads(
                self._vault_request('POST', '/v1/sys/capabilities-self',
                                    body=json.dumps({'path': path}))
            )
            logger.debug('Capabilities: %s', caps['capabilities'])
            if 'read' in caps['capabilities']:
                roles.append(rname)
        logger.debug('Vault Roles for %s mountpoint: %s', mpoint, roles)
        return roles

    def get_creds(self, mountpoint, role_name, iam=False, store_role=True):
        """
        Given an AWS secret backend mountpoint and a role name, return export
        statements to set credentials for that role.

        :param mountpoint: AWS backend mountpoint to read from (account)
        :type mountpoint: str
        :param role_name: Vault role name to get creds for
        :type role_name: str
        :param iam: Whether to get actual IAM User creds; if false, STS creds
        :type iam: bool
        :param store_role: if True, store role selection in config file and
          use config file for default role selection
        :type store_role: bool
        :return: string of bash source code to export credentials for the role
        :rtype: str
        """
        if role_name is None and not store_role:
            raise VaultException(
                "When running with -R/--no-stored-role, you must specify a "
                "Vault role name to get credentials for."
            )
        if role_name is None:
            role_name = self._get_conf('roles', mountpoint)
            iam = self._get_conf_bool('use_iam', mountpoint)
        if role_name is None:
            # not stored in config
            raise VaultException(
                "No role name specified on command line, and no default "
                "role name for account '%s' is stored in the config file. "
                "You must explicitly specify a role name; it will be stored "
                "as the default for future invocations." % mountpoint
            )
        if iam:
            path = "/v1/%screds/%s" % (mountpoint, role_name)
        else:
            path = "/v1/%ssts/%s" % (mountpoint, role_name)
            sys.stderr.write(bold(
                "WARNING: STS credentials cannot call any IAM APIs or any "
                "STS APIs other than AssumeRole or GetCallerIdentity. If you "
                "need to call IAM APIs or other STS APIs, please generate new "
                "credentials with the --iam option."
            ) + "\n")
        logger.info('Getting AWS credentials via path: %s', path)
        creds = json.loads(self._vault_request('GET', path))
        data = creds.get('data', {})
        if 'lease_id' not in creds or 'access_key' not in data:
            raise VaultException(
                "Requested credentials from Vault but received an invalid "
                "response: %s" % creds
            )
        sys.stderr.write("Got credentials for account '%s' role '%s'\n" % (
            mountpoint, role_name
        ))
        sys.stderr.write(
            "Request ID (for troubleshooting): %s\n" % creds['request_id']
        )
        sys.stderr.write(
            "Lease (credentials) will expire in: %s\n" % humantime(
                creds['lease_duration']
            )
        )
        if creds.get('renewable', False):
            sys.stderr.write(
                "To renew, run: vault renew %s\n" % creds['lease_id']
            )
        region = os.environ.get(
            'AWS_REGION',
            os.environ.get('AWS_DEFAULT_REGION', None)
        )
        if region is None:
            region = self._region
        exports = [
            "export AWS_REGION='%s'" % region,
            "export AWS_DEFAULT_REGION='%s'" % region,
            "export AWS_ACCESS_KEY_ID='%s'" % data['access_key'],
            "export AWS_SECRET_ACCESS_KEY='%s'" % data['secret_key']
        ]
        sess = data.get('security_token', None)
        if sess is not None:
            exports.append("export AWS_SESSION_TOKEN='%s'" % sess)
        else:
            exports.append("unset AWS_SESSION_TOKEN")
        sys.stderr.write(
            "Outputting the following for shell evaluation:"
            "\n%s\n" % "\n".join(["\t%s" % x for x in exports])
        )
        if store_role:
            self._set_conf('roles', mountpoint, role_name)
            self._set_conf_bool('iam', mountpoint, iam)
        return "\n".join(exports)

    def mountpoint_for_account(self, acct_name):
        """
        Given an account name input on the command line, return the Vault
        mountpoint corresponding to that account name.

        :param acct_name: account name as input on the CLI
        :type acct_name: str
        :return: Vault mountpoint for that account
        :rtype: str
        """
        mpoints = self._get_aws_mountpoints()
        if acct_name in mpoints:
            logger.info('Account name "%s" mountpoint: %s',
                        acct_name, mpoints[acct_name])
            return mpoints[acct_name]
        logger.warning('Account name "%s" not found in list of %d mountpoints; '
                       'using as an explicit mountpoint for AWS backend.')
        if not acct_name.endswith('/'):
            acct_name += '/'
        return acct_name


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
    epil = dedent("""
    Usage Examples
    --------------
    
    First, export the address to your Vault instance and authenticate. It's
    recommended that you set VAULT_ADDR in your shell profile (~/.bashrc):
        export VAULT_ADDR=https://my.vault:8200
        vault auth
    
    Then, add the wrapper function to your ~/.bashrc:
        ./vault-aws-creds.py --wrapper-func >> ~/.bashrc
    
    List available accounts:
        vault-aws-creds
    
    List available roles for account "dev":
        vault-aws-creds --roles dev
    
    Get STS credentials for the "foo" role in the "dev" account:
        vault-aws-creds dev foo
    
    Get IAM User credentials for the "foo" role in the "dev" account:
        vault-aws-creds --iam dev foo
    
    Get STS credentials for your last-used role in the "dev" account:
        vault-aws-creds dev
    
    The latest source can be found at:
    <%s>
    """ % _SRC_URL)
    p = argparse.ArgumentParser(
        description='Retrieve temporary AWS credentials from Vault and print '
                    'bash export lines for them. Intended to be run from a '
                    'bash wrapper function.',
        epilog=epil, formatter_class=argparse.RawTextHelpFormatter
    )
    p.add_argument('-w', '--wrapper-func', dest='show_wrapper',
                   action='store_true', default=False, help='print bash wrapper'
                   ' function to STDOUT and exit')
    p.add_argument('-v', '--verbose', dest='verbose', action='count', default=0,
                   help='verbose output. specify twice for debug-level output.')
    p.add_argument('-V', '--version', action='store_true', default=False,
                   help='Print version number and exit', dest='version')
    conf = os.path.abspath(os.path.expanduser('~/.vault-aws-creds.conf'))
    p.add_argument('-c', '--config-file', dest='config', action='store',
                   type=str, default=conf,
                   help='Path to config file (default: %s)' % conf)
    p.add_argument('--called-from-wrapper', dest='wrapper_called',
                   action='store_true', default=False, help='DO NOT USE')
    p.add_argument('-r', '--region', dest='region', action='store', type=str,
                   default=None,
                   help='AWS_REGION to export if not already set')
    p.add_argument('ACCOUNT', action='store', default=None, nargs='?',
                   help='AWS account name (Vault AWS backend mount point, or '
                        'mount point after "aws_" prefix); if omitted, all '
                        'accounts you have access to will be listed.')
    p.add_argument('--roles', dest='list_roles', action='store_true',
                   default=False, help='List available roles for account')
    p.add_argument('--iam', dest='iam', action='store_true', default=False,
                   help='If specified, get IAM User credentials. Otherwise, get'
                        ' STS credentials.')
    p.add_argument('-R', '--no-stored-role', dest='store_role',
                   action='store_false', default=True,
                   help='Do not store role selection in, or use previous role '
                        'selection from, config file')
    p.add_argument('ROLE', action='store', default=None, nargs='?',
                   help='Vault role name to get creds for in the account; '
                        'if --no-stored-role is not specified, the role name '
                        'for each account will be stored to and retrieved from '
                        'the config file.')
    args = p.parse_args(argv)
    if args.version:
        sys.stderr.write("vault-aws-creds.py version %s\n" % __version__)
        raise SystemExit(1)
    return args

if __name__ == "__main__":
    args = parse_args(sys.argv[1:])

    # set logging level
    if args.verbose > 1:
        set_log_debug()
    elif args.verbose == 1:
        set_log_info()

    try:
        exporter = VaultAwsCredExporter(args.config, args.region)

        if args.show_wrapper:
            print(exporter.bash_wrapper)
            raise SystemExit(1)
        if not args.wrapper_called:
            sys.stderr.write(
                bold('vault-aws-creds.py should be called through a bash wrapper '
                     'function; run with "-w" to output the appropriate '
                     'function.') + "\n"
            )
        if args.ACCOUNT is None:
            mpoints = exporter._get_aws_mountpoints()
            mpoint_listing = {}
            for name, mpoint in mpoints.items():
                if mpoint not in mpoint_listing:
                    mpoint_listing[mpoint] = []
                mpoint_listing[mpoint].append(name)
            sys.stderr.write("Available Accounts:\n")
            for mpoint in sorted(mpoint_listing.keys()):
                sys.stderr.write(' a.k.a. '.join(
                    ['"%s"' % x for x in mpoint_listing[mpoint]]
                ) + "\n")
            raise SystemExit(1)
        # ok, we have an account name
        acct = exporter.mountpoint_for_account(args.ACCOUNT)
        logger.info('Using mountpoint: %s', acct)
        if args.list_roles:
            sys.stderr.write("Available Vault Roles for Account '%s':\n" % acct)
            for rname in exporter.list_roles(acct):
                sys.stderr.write(rname + "\n")
            raise SystemExit(1)
        print(exporter.get_creds(acct, args.ROLE, iam=args.iam,
                                 store_role=args.store_role))
    except VaultException as ex:
        sys.stderr.write("ERROR: %s\n" % ex)
        raise SystemExit(1)
