#!/usr/bin/env python

import time
import urllib2
import \
    ambari_simplejson as json  # simplejson is much faster comparing to Python 2.6 json module and has the same functions set.
import logging
import traceback

logger = logging.getLogger()

from resource_management.libraries.functions.namenode_ha_utils import get_all_namenode_addresses
from resource_management.libraries.functions.curl_krb_request import curl_krb_request
from resource_management.libraries.functions.curl_krb_request import DEFAULT_KERBEROS_KINIT_TIMER_MS
from resource_management.libraries.functions.curl_krb_request import KERBEROS_KINIT_TIMER_PARAMETER
from resource_management.core.environment import Environment

LABEL = 'The follwing subdirectories: "{d}" in the root directory: "{r}" are over the configured quota capacity threshold: {t}%'
HDFS_SITE_KEY = '{{hdfs-site}}'

RESULT_STATE_UNKNOWN = 'UNKNOWN'
RESULT_STATE_SKIPPED = 'SKIPPED'

NN_HTTP_ADDRESS_KEY = '{{hdfs-site/dfs.namenode.http-address}}'
NN_HTTPS_ADDRESS_KEY = '{{hdfs-site/dfs.namenode.https-address}}'
NN_HTTP_POLICY_KEY = '{{hdfs-site/dfs.http.policy}}'
NN_CHECKPOINT_TX_KEY = '{{hdfs-site/dfs.namenode.checkpoint.txns}}'
NN_CHECKPOINT_PERIOD_KEY = '{{hdfs-site/dfs.namenode.checkpoint.period}}'

LOCATION_QUOTA_KEY = 'location.quota'
LOCATION_QUOTA_DEFAULT = '/user'

QUOTA_WARN_KEY = 'quota.warning.threshold'
QUOTA_WARN_DEFAULT = 70

QUOTA_CRIT_KEY = 'quota.critical.threshold'
QUOTA_CRIT_DEFAULT = 90

CONNECTION_TIMEOUT_KEY = 'connection.timeout'
CONNECTION_TIMEOUT_DEFAULT = 5.0

KERBEROS_KEYTAB = '{{hdfs-site/dfs.web.authentication.kerberos.keytab}}'
KERBEROS_PRINCIPAL = '{{hdfs-site/dfs.web.authentication.kerberos.principal}}'
SECURITY_ENABLED_KEY = '{{cluster-env/security_enabled}}'
SMOKEUSER_KEY = "{{cluster-env/smokeuser}}"
EXECUTABLE_SEARCH_PATHS = '{{kerberos-env/executable_search_paths}}'

logger = logging.getLogger('ambari_alerts')


def get_tokens():
    """
    Returns a tuple of tokens in the format {{site/property}} that will be used
    to build the dictionary passed into execute
    """
    return (HDFS_SITE_KEY, NN_HTTP_ADDRESS_KEY, NN_HTTPS_ADDRESS_KEY, NN_HTTP_POLICY_KEY, EXECUTABLE_SEARCH_PATHS,
            NN_CHECKPOINT_TX_KEY, NN_CHECKPOINT_PERIOD_KEY, KERBEROS_KEYTAB, KERBEROS_PRINCIPAL, SECURITY_ENABLED_KEY,
            SMOKEUSER_KEY)


def execute(configurations={}, parameters={}, host_name=None):
    """
    Returns a tuple containing the result code and a pre-formatted result label

    Keyword arguments:
    configurations (dictionary): a mapping of configuration key to value
    parameters (dictionary): a mapping of script parameter key to value
    host_name (string): the name of this host where the alert is running
    """

    if configurations is None:
        return (('UNKNOWN', ['There were no configurations supplied to the script.']))

    uri = None
    scheme = 'http'
    http_uri = None
    https_uri = None
    http_policy = 'HTTP_ONLY'

    # hdfs-site is required
    if not HDFS_SITE_KEY in configurations:
        return (RESULT_STATE_UNKNOWN, ['{0} is a required parameter for the script'.format(HDFS_SITE_KEY)])

    if NN_HTTP_POLICY_KEY in configurations:
        http_policy = configurations[NN_HTTP_POLICY_KEY]

    if NN_CHECKPOINT_TX_KEY in configurations:
        checkpoint_tx = configurations[NN_CHECKPOINT_TX_KEY]

    if NN_CHECKPOINT_PERIOD_KEY in configurations:
        checkpoint_period = configurations[NN_CHECKPOINT_PERIOD_KEY]

    if SMOKEUSER_KEY in configurations:
        smokeuser = configurations[SMOKEUSER_KEY]

    executable_paths = None
    if EXECUTABLE_SEARCH_PATHS in configurations:
        executable_paths = configurations[EXECUTABLE_SEARCH_PATHS]

    security_enabled = False
    if SECURITY_ENABLED_KEY in configurations:
        security_enabled = str(configurations[SECURITY_ENABLED_KEY]).upper() == 'TRUE'

    kerberos_keytab = None
    if KERBEROS_KEYTAB in configurations:
        kerberos_keytab = configurations[KERBEROS_KEYTAB]

    kerberos_principal = None
    if KERBEROS_PRINCIPAL in configurations:
        kerberos_principal = configurations[KERBEROS_PRINCIPAL]
        kerberos_principal = kerberos_principal.replace('_HOST', host_name)

    # parse script arguments
    connection_timeout = CONNECTION_TIMEOUT_DEFAULT
    if CONNECTION_TIMEOUT_KEY in parameters:
        connection_timeout = float(parameters[CONNECTION_TIMEOUT_KEY])

    location_quota = LOCATION_QUOTA_DEFAULT
    if LOCATION_QUOTA_KEY in parameters:
        location_quota = str(parameters[LOCATION_QUOTA_KEY])

    quota_warning = QUOTA_WARN_DEFAULT
    if QUOTA_WARN_KEY in parameters:
        quota_warning = float(parameters[QUOTA_WARN_KEY])

    quota_critical = QUOTA_CRIT_DEFAULT
    if QUOTA_CRIT_KEY in parameters:
        quota_critical = float(parameters[QUOTA_CRIT_KEY])

    kinit_timer_ms = parameters.get(KERBEROS_KINIT_TIMER_PARAMETER, DEFAULT_KERBEROS_KINIT_TIMER_MS)

    # determine the right URI and whether to use SSL
    hdfs_site = configurations[HDFS_SITE_KEY]

    scheme = "https" if http_policy == "HTTPS_ONLY" else "http"

    nn_addresses = get_all_namenode_addresses(hdfs_site)
    for nn_address in nn_addresses:
        if nn_address.startswith(host_name + ":"):
            uri = nn_address
            break
    if not uri:
        return (RESULT_STATE_SKIPPED,
                ['NameNode on host {0} not found (namenode adresses = {1})'.format(host_name, ', '.join(nn_addresses))])

    current_time = int(round(time.time() * 1000))

    all_users_qry = "{0}://{1}/webhdfs/v1".format(scheme, uri) + location_quota + "?op=LISTSTATUS"   

    # start out assuming an OK status
    label = None
    result_code = "OK"

    try:
        # curl requires an integer timeout
        curl_connection_timeout = int(connection_timeout)

        all_users_response, error_msg, time_millis = curl_krb_request("/tmp", kerberos_keytab,
                                                                          kerberos_principal, all_users_qry,
                                                                          "hdfs_space_quota_alert", executable_paths,
                                                                          False,
                                                                          "HDFS Space Quota", smokeuser,
                                                                          connection_timeout=curl_connection_timeout,
                                                                          kinit_timer_ms=kinit_timer_ms)

        all_users_response_json = json.loads(all_users_response)

	# if namenode is not active then skip
        if 'FileStatuses' not in all_users_response_json:
                return (RESULT_STATE_SKIPPED, ['NameNode is not active'])

	users = []
	for filestatus in all_users_response_json['FileStatuses']['FileStatus']:
    		users.append(filestatus.get("pathSuffix"))

        critical = []
        warning = []
       	ok = []
        for user in users:
    
		current_quota_qry = "{0}://{1}/webhdfs/v1".format(scheme, uri) + location_quota + "/" + user + "?op=GETCONTENTSUMMARY"
		current_quota_response, error_msg, time_millis = curl_krb_request("/tmp", kerberos_keytab,
                                                                          kerberos_principal, current_quota_qry,
                                                                          "hdfs_space_quota_alert", executable_paths,
                                                                          False,
                                                                          "HDFS Space Quota", smokeuser,
                                                                          connection_timeout=curl_connection_timeout,
                                                                          kinit_timer_ms=kinit_timer_ms)
		
        	current_quota_response_json = json.loads(current_quota_response)
        	result_in_percent = int(float(current_quota_response_json["ContentSummary"]["spaceConsumed"]) / float(current_quota_response_json["ContentSummary"]["spaceQuota"]) * 100)
		
        	if (result_in_percent >= int(quota_critical)):
			critical.append(user)
        	elif (result_in_percent >= int(quota_warning)):
            		warning.append(user)
        	else:
            		ok.append(user)

	if len(critical) > 0:
        	result_code = 'CRITICAL'
                criticalusers = ",".join([str(x) for x in critical])
                label = LABEL.format(d=criticalusers,r=location_quota,t=quota_critical)
	elif len(warning) > 0:
		result_code = 'WARNING'
		warningusers = ",".join([str(x) for x in warning])
                label = LABEL.format(d=warningusers,r=location_quota,t=quota_warning)
	else:
                result_code = "OK"
                label = 'All top-level user subdirectories in "{d}" are within configured quota capacity threshold'.format(d=location_quota)

    except:
        label = traceback.format_exc()
        result_code = 'UNKNOWN'

    return ((result_code, [label]))
