#!/usr/bin/env python3
#
#
# Cluster testing helper
#
# Requires:
#  trivup python module
#  gradle in your PATH

from trivup.trivup import Cluster, UuidAllocator
from trivup.apps.ZookeeperApp import ZookeeperApp
from trivup.apps.KafkaBrokerApp import KafkaBrokerApp
from trivup.apps.KerberosKdcApp import KerberosKdcApp
from trivup.apps.SslApp import SslApp

import os, sys, json, argparse, re
from jsoncomment import JsonComment
from textwrap import dedent


def version_as_list (version):
    if version == 'trunk':
        return [sys.maxint]
    return [int(a) for a in re.findall('\d+', version)][0:3]

def read_scenario_conf(scenario):
    """ Read scenario configuration from scenarios/<scenario>.json """
    parser = JsonComment(json)
    with open(os.path.join('scenarios', scenario + '.json'), 'r') as f:
        return parser.load(f)

class LibrdkafkaTestCluster(Cluster):
    def __init__(self, version, conf={}, num_brokers=3, debug=False,
                 scenario="default"):
        """
        @brief Create, deploy and start a Kafka cluster using Kafka \p version

        Supported \p conf keys:
         * security.protocol - PLAINTEXT, SASL_PLAINTEXT, SASL_SSL

        \p conf dict is passed to KafkaBrokerApp classes, etc.
        """

        super(LibrdkafkaTestCluster, self).__init__(self.__class__.__name__,
                                                    os.environ.get('TRIVUP_ROOT', 'tmp'), debug=debug)

        # Read trivup config from scenario definition.
        defconf = read_scenario_conf(scenario)
        defconf.update(conf)

        # Enable SSL if desired
        if 'SSL' in conf.get('security.protocol', ''):
            self.ssl = SslApp(self, defconf)

        self.brokers = list()

        # One ZK (from Kafka repo)
        ZookeeperApp(self)

        # Start Kerberos KDC if GSSAPI (Kerberos) is configured
        if 'GSSAPI' in defconf.get('sasl_mechanisms', []):
            kdc = KerberosKdcApp(self, 'MYREALM')
            # Kerberos needs to be started prior to Kafka so that principals
            # and keytabs are available at the time of Kafka config generation.
            kdc.start()

        # Brokers
        defconf.update({'replication_factor': min(num_brokers, 3),
                        'version': version,
                        'security.protocol': 'PLAINTEXT'})
        self.conf = defconf

        for n in range(0, num_brokers):
            # Configure rack & replica selector if broker supports fetch-from-follower
            if version_as_list(version) >= [2, 4, 0]:
                defconf.update({'conf': ['broker.rack=RACK${appid}', 'replica.selector.class=org.apache.kafka.common.replica.RackAwareReplicaSelector']})
            self.brokers.append(KafkaBrokerApp(self, defconf))


    def bootstrap_servers (self):
        """ @return Kafka bootstrap servers based on security.protocol """
        all_listeners = (','.join(self.get_all('advertised_listeners', '', KafkaBrokerApp))).split(',')
        return ','.join([x for x in all_listeners if x.startswith(self.conf.get('security.protocol'))])


def result2color (res):
    if res == 'PASSED':
        return '\033[42m'
    elif res == 'FAILED':
        return '\033[41m'
    else:
        return ''

def print_test_report_summary (name, report):
    """ Print summary for a test run. """
    passed = report.get('PASSED', False)
    if passed:
        resstr = '\033[42mPASSED\033[0m'
    else:
        resstr = '\033[41mFAILED\033[0m'

    print('%6s  %-50s: %s' % (resstr, name, report.get('REASON', 'n/a')))
    if not passed:
        # Print test details
        for name,test in report.get('tests', {}).items():
            testres = test.get('state', '')
            if testres == 'SKIPPED':
                continue
            print('%s   --> %-20s \033[0m' % \
                  ('%s%s\033[0m' % \
                   (result2color(test.get('state', 'n/a')),
                    test.get('state', 'n/a')),
                   test.get('name', 'n/a')))
        print('%8s --> %s/%s' %
              ('', report.get('root_path', '.'), 'stderr.log'))


def print_report_summary (fullreport):
    """ Print summary from a full report suite """
    suites = fullreport.get('suites', list())
    print('#### Full test suite report (%d suite(s))' % len(suites))
    for suite in suites:
        for version,report in suite.get('version', {}).items():
            print_test_report_summary('%s @ %s' % \
                                      (suite.get('name','n/a'), version),
                                      report)

    pass_cnt = fullreport.get('pass_cnt', -1)
    if pass_cnt == 0:
        pass_clr = ''
    else:
        pass_clr = '\033[42m'

    fail_cnt = fullreport.get('fail_cnt', -1)
    if fail_cnt == 0:
        fail_clr = ''
    else:
        fail_clr = '\033[41m'

    print('#### %d suites %sPASSED\033[0m, %d suites %sFAILED\033[0m' % \
          (pass_cnt, pass_clr, fail_cnt, fail_clr))


def create_selfsigned_cert(ssl, cn):
    """
        Create certificate/keys, in multiple formats (PEM, DER, PKCS#12),
        for @param cn.
        It differs from SSLApp.create_cert because the certificate generated
        is not correctly signed by the CA cert; helpful for tests that should fail.
        This is typically used for clients.
        The PKCS contains private key, public key, and CA cert
        @returns {'priv': {'pem': .., 'der': ..},
                  'pub': {'pem': .., 'der': ..},
                  'pkcs': '..',
                  'req': '..',
                  'password': '..'}
        """
    password = ssl.conf.get('ssl_key_pass')

    ret = {'priv': {'pem': ssl.mkpath('%s-priv.pem' % cn),
                    'der': ssl.mkpath('%s-priv.der' % cn)},
           'pub': {'pem': ssl.mkpath('%s-pub.pem' % cn),
                   'der': ssl.mkpath('%s-pub.der' % cn)},
           'pkcs': ssl.mkpath('%s.pfx' % cn),
           'req': ssl.mkpath('%s.req' % cn),
           'password': password}

    ssl.dbg('Generating key for %s: %s' % (cn, ret['priv']['pem']))
    ssl.exec_cmd('openssl genrsa -des3 -passout "pass:%s" -out "%s" 2048' %  # noqa: E501
                  (password, ret['priv']['pem']))

    ssl.dbg('Generating request for %s: %s' % (cn, ret['req']))
    ssl.exec_cmd('openssl req -passin "pass:%s" -passout "pass:%s" -key "%s" -new -out "%s" -subj "%s"' %  # noqa: E501
                  (password, password,
                   ret['priv']['pem'], ret['req'], ssl.mksubj(cn)))

    ssl.dbg('Signing key for %s' % (cn))
    ssl.exec_cmd('openssl x509 -req -passin "pass:%s" -in "%s" -signkey "%s" -out "%s"' %  # noqa: E501
                  (password,
                   ret['req'], ret['priv']['pem'], ret['pub']['pem']))

    ssl.dbg('Converting public-key X.509 to DER for %s' % cn)
    ssl.exec_cmd('openssl x509 -outform der -in "%s" -out "%s"' %  # noqa: E501
                  (ret['pub']['pem'], ret['pub']['der']))

    ssl.dbg('Converting private-key X.509 to DER for %s' % cn)
    ssl.exec_cmd('openssl rsa -outform der -passin "pass:%s" -in "%s" -out "%s"' %  # noqa: E501
                  (password, ret['priv']['pem'], ret['priv']['der']))

    ssl.dbg('Creating PKCS#12 for %s in %s' % (cn, ret['pkcs']))
    ssl.exec_cmd('openssl pkcs12 -export -out "%s" -inkey "%s" -in "%s" -CAfile "%s" -certfile "%s" -passin "pass:%s" -passout "pass:%s"' %  # noqa: E501
                  (ret['pkcs'],
                   ret['priv']['pem'],
                   ret['pub']['pem'],
                   ret['pub']['pem'],
                   ret['pub']['pem'],
                   password, password))
    return ret


def create_cert_via_intermediate(ssl, cn):
    """
    Create certificate/keys, in multiple formats (PEM, DER, PKCS#12),
    for @param cn.
    It differs from SSLApp.create_cert in that it returns a certificate chain, signed
    through an intermediate.
    This is typically used for clients.
    The PKCS contains private key, public key, and CA cert
    @returns {'priv': {'pem': .., 'der': ..},
              'pub': {'pem': .., 'der': ..},
              'pkcs': '..',
              'req': '..',
              'password': '..'}
    """

    password = ssl.conf.get('ssl_key_pass')

    ret = {'priv': {'pem': ssl.mkpath('%s-priv.pem' % cn),
                    'der': ssl.mkpath('%s-priv.der' % cn)},
           'pub': {'pem': ssl.mkpath('%s-pub.pem' % cn),
                   'der': ssl.mkpath('%s-pub.der' % cn)},
           'intermediate_priv': {'pem': ssl.mkpath('%s-intermediate-priv.pem' % cn),
                                 'der': ssl.mkpath('%s-intermediate-priv.der' % cn)},
           'intermediate_pub': {'pem': ssl.mkpath('%s-intermediate-pub.pem' % cn),
                                'der': ssl.mkpath('%s-intermediate-pub.der' % cn)},
           'req': ssl.mkpath('%s.req' % cn),
           'intermediate_req': ssl.mkpath('%s-intermediate.req' % cn),
           'password': password}

    ssl_cfg = ssl.mkpath('%s.cnf' % cn)
    with open(ssl_cfg, 'w') as f:
        f.write(dedent("""
            [req]
            distinguished_name=dn
            [ dn ]
            [ ext ]
            basicConstraints=CA:TRUE,pathlen:0
        """))

    ssl.dbg('Generating key for %s intermediate: %s' % (cn, ret['intermediate_priv']['pem']))
    ssl.exec_cmd('openssl genrsa -out "%s" 2048' % # noqa: E501
                 (ret['intermediate_priv']['pem']))
    ssl.dbg('Generating request for %s: %s' % (cn, ret['req']))
    ssl.exec_cmd('openssl req -config "%s" -extensions ext -key "%s" -new -out "%s" -subj "%s"' %  # noqa: E501
             (ssl_cfg, ret['intermediate_priv']['pem'], ret['intermediate_req'], ssl.mksubj('%s-intermediate' %(cn))))
    ssl.dbg('Signing key for %s intermediate' % (cn))
    ssl.exec_cmd('openssl x509 -req -extfile "%s" -extensions ext -passin "pass:%s" -in "%s" -CA "%s" -CAkey "%s" -CAserial "%s" -out "%s"' %  # noqa: E501
                 (ssl_cfg, password,
                  ret['intermediate_req'], ssl.ca['pem'], ssl.ca['key'],
                  ssl.ca['srl'], ret['intermediate_pub']['pem']))
    ssl.dbg('Converting public-key X.509 to DER for %s intermediate' % cn)
    ssl.exec_cmd('openssl x509 -outform der -in "%s" -out "%s"' %  # noqa: E501
                 (ret['intermediate_pub']['pem'], ret['intermediate_pub']['der']))

    ssl.dbg('Converting private-key X.509 to DER for %s intermediate' % cn)
    ssl.exec_cmd('openssl rsa -outform der -passin "pass:%s" -in "%s" -out "%s"' %  # noqa: E501
                 (password, ret['intermediate_priv']['pem'], ret['intermediate_priv']['der']))

    ssl.dbg('Generating key for %s: %s' % (cn, ret['priv']['pem']))
    ssl.exec_cmd('openssl genrsa -des3 -passout "pass:%s" -out "%s" 2048' %  # noqa: E501
                  (password, ret['priv']['pem']))

    ssl.dbg('Generating request for %s: %s' % (cn, ret['req']))
    ssl.exec_cmd('openssl req -passin "pass:%s" -passout "pass:%s" -key "%s" -new -out "%s" -subj "%s"' %  # noqa: E501
                  (password, password,
                   ret['priv']['pem'], ret['req'], ssl.mksubj(cn)))

    ssl.dbg('Signing key for %s' % (cn))
    ssl.exec_cmd('openssl x509 -req -in "%s" -CA "%s" -CAkey "%s" -CAserial "%s" -out "%s"' %  # noqa: E501
                  (ret['req'], ret['intermediate_pub']['pem'], ret['intermediate_priv']['pem'],
                   ssl.ca['srl'], ret['pub']['pem']))

    ssl.dbg('Converting public-key X.509 to DER for %s' % cn)
    ssl.exec_cmd('openssl x509 -outform der -in "%s" -out "%s"' %  # noqa: E501
                  (ret['pub']['pem'], ret['pub']['der']))

    ssl.dbg('Converting private-key X.509 to DER for %s' % cn)
    ssl.exec_cmd('openssl rsa -outform der -passin "pass:%s" -in "%s" -out "%s"' %  # noqa: E501
                  (password, ret['priv']['pem'], ret['priv']['der']))

    return ret


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Show test suite report')
    parser.add_argument('report', type=str, nargs=1,
                        help='Show summary from test suites report file')

    args = parser.parse_args()

    passed = False
    with open(args.report[0], 'r') as f:
        passed = print_report_summary(json.load(f))

    if passed:
        sys.exit(0)
    else:
        sys.exit(1)
