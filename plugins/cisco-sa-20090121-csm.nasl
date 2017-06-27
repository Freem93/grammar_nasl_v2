#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69303);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 20:59:28 $");

  script_cve_id("CVE-2008-3820");
  script_bugtraq_id(33381);
  script_osvdb_id(52316);
  script_xref(name:"CISCO-BUG-ID", value:"CSCsv66897");
  script_xref(name:"IAVA", value:"2009-A-0011");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20090121-csm");

  script_name(english:"Cisco Security Manager MySQL Accessible Without Authentication (cisco-sa-20090121-csm)");
  script_summary(english:"Tries to connect to the CSM MySQL server");

  script_set_attribute(attribute:"synopsis", value:"The remote database server can be accessed without a password.");
  script_set_attribute(
    attribute:"description",
    value:
"The version of Cisco Security Manager (CSM) running on the remote host
is using a vulnerable version of Cisco IPS Event Viewer (IEV).  IEV is
included with CSM by default.  When the IEV server is accessed remotely,
it opens up TCP ports that allow access to the MySQL or IEV server
without authentication.  A remote, unauthenticated attacker could
exploit this to gain root access to the IEV database and server. 

Note that the MySQL service uses SSL/TLS and is not directly accessible
using the official MySQL client."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/csa/cisco-sa-20090121-csm.html");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions of Cisco Security Manager
listed in Cisco Security Advisory cisco-sa-20090121-csm."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:security_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports(60002);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("mysql_func.inc");

##
# runs "show databases". assumes that the caller has already logged
# into a mysql server
#
# @return a list of databases if the command succeeded,
#         NULL otherwise.
##
function show_databases()
{
  local_var req, res, databases, loop;

  mysql_send_packet(data:mkbyte(3)+'show databases', num:0);
  res = mysql_recv_packet();

  databases = make_list();

  if (!isnull(res) && res['num'] == 1)
  {
    res = mysql_recv_packet();
    if (!isnull(res))
    {
      res = mysql_recv_packet();
      if (!isnull(res) && getbyte(blob:res['data'], pos:0) == 254)
      {
        loop = 1;
        while (loop)
        {
          res = mysql_recv_packet();
          if (!isnull(res) && getbyte(blob:res['data'], pos:0) != 254)
            databases = make_list(databases, substr(res['data'], 1, res['len']-1));
          else
            loop = 0;
        }
      }
    }
  }

  if (max_index(databases) > 0)
    return databases;
  else
    return NULL;
}

##
# a combination of mysql_init() and mysql_open() from mysql_func.inc.
# the difference is this function always tries negotiate TLSv1 as soon
# as the TCP handshake completes
#
# @anonparam port port number to connect to
# @remark this function exits if it fails for any reason
##
function _mysql_open()
{
  local_var hip, l, port, soc, error, audit_msg;
  port = _FCT_ANON_ARGS[0];

  _mysql["port"] = port;
  soc = open_sock_tcp(port, transport:ENCAPS_TLSv1);
  if (!soc)
    audit(AUDIT_SOCK_FAIL, port);
  else
    _mysql["soc"] = soc;

  hip = mysql_recv_packet();
  if (isnull(hip))
  {
    mysql_close();
    audit(AUDIT_RESP_BAD, port, 'Handshake Initialization Packet');
  }

  if (mysql_is_error_packet(packet:hip))
  {
    _mysql["err"] = hip;

    error = mysql_get_last_error();
    audit_msg =
      'Error connecting to server on port ' + port + ':\n' +
      'Error code: ' +  error['num'] + '\n' +
      'Error message: ' +  error['msg'];
    exit(0, audit_msg);
  }
  else _mysql["err"] = NULL;

  _mysql["proto"]     = getbyte(blob:hip["data"], pos:0);
  _mysql["ver"]       = mysql_get_null_string(blob:hip["data"], pos:1);
  l = strlen(_mysql["ver"]);
  _mysql["thread_id"] = getdword(blob:hip["data"], pos:2+l);
  _mysql["salt"]      = substr(hip["data"], 6+l, 13+l);
  _mysql["caps"]      = getword(blob:hip["data"], pos:15+l);
  _mysql["lang"]      = getbyte(blob:hip["data"], pos:17+l);
  _mysql["status"]    = getword(blob:hip["data"], pos:18+l);
  # nb: I didn't find this addition to the salt documented on mysql.com,
  #     but Net::MySQL uses it.
  if (mysql_is_proto41_supported() && strlen(hip["data"]) > 44+l)
    _mysql["salt2"] = substr(hip["data"], 33+l, 44+l);

  # Cache server-specific info in the KB.
  replace_kb_item(name:'mysql/'+port+'/port', value:_mysql["port"]);
  replace_kb_item(name:'mysql/'+port+'/proto', value:_mysql["proto"]);
  replace_kb_item(name:'mysql/'+port+'/ver', value:_mysql["ver"]);
  replace_kb_item(name:'mysql/'+port+'/caps', value:_mysql["caps"]);
  replace_kb_item(name:'mysql/'+port+'/lang', value:_mysql["lang"]);
  replace_kb_item(name:'mysql/'+port+'/status', value:_mysql["status"]);
}

if (supplied_logins_only)
  audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# the unprotected MySQL server uses SSL/TLS and listens on TCP 60002.
# if the service on this port has already been identified, only continue
# with this check if both of those characteristics are seen
port = 60002;
svc = get_kb_item('Known/tcp/' + port);
if (isnull(svc))
{
  # if there has been no service identified on this port,
  # check to see if it is closed
  if (!get_port_state(port))
    audit(AUDIT_PORT_CLOSED, port);
  else
    svc_unknown = TRUE;

  ssl_detected = FALSE;
}
else
{
  # if there was a service identified on this port, bail out if it
  # is not MySQL or if it is not using SSL/TLS
  if (svc != 'mysql')
    audit(AUDIT_NOT_LISTEN, 'MySQL', port);
  else
    svc_unknown = FALSE;

  ssl_ports = get_kb_list('Transport/SSL');
  foreach ssl_port (ssl_ports)
  {
    if (ssl_port == port)
    {
      ssl_detected = TRUE;
      break;
    }
  }

  if (!ssl_detected)
    audit(AUDIT_NOT_LISTEN, 'An SSL/TLS service', port);
}

_mysql_open(port); # this function exits if it fails
if (svc_unknown)
  register_service(port:port, proto:'mysql');
if (!ssl_detected)
  set_kb_item(name:'Transport/SSL', value:port);

expected_dbs = make_array(
  'alarmDB', TRUE,
  'compressedDB', TRUE,
  'mysql', TRUE
);
num_db_matches = 0;

user = 'root';
caps = mysql_get_caps();
caps = caps & (0xFFFFFFFF - CLIENT_NO_SCHEMA - CLIENT_CONNECT_WITH_DB);
if (mysql_login(user:user, flags:caps) == 1)
{
  databases = show_databases();
  if (!isnull(databases))
  {
    info = "";
    foreach db (databases)
    {
      info += '  - ' + db + '\n';

      if (expected_dbs[db])
        num_db_matches++;
    }

    if (info)
    {
      report +=
        '\nNessus was able to log into the MySQL server without authentication' +
        '\nand get the list of databases :\n\n' +
        info;
      set_kb_item(name: 'MySQL/no_passwd/'+port, value: user);
    }
  }
}
else
{
  error = mysql_get_last_error();
}

mysql_close();

if (isnull(report))
{
  audit(AUDIT_LISTEN_NOT_VULN, 'MySQL', port);
}
# "show databases" appears to have worked, but did not give results consistent with CVE-2008-3820
else if (
  report_paranoia < 2 &&
  num_db_matches != max_index(keys(expected_dbs))
)
{
  audit(AUDIT_RESP_BAD, port, '"show databases"');
}

if (report_verbosity > 0)
  security_warning(port:port, extra:report);
else
  security_warning(port);

