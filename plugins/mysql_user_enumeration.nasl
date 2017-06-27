#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64263);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/10/05 20:44:34 $");

  script_cve_id("CVE-2012-5615");
  script_bugtraq_id(56766);
  script_osvdb_id(88067);
  script_xref(name:"EDB-ID", value:"23081");

  script_name(english:"MySQL Protocol Remote User Enumeration");
  script_summary(english:"Tries to enumerate usernames");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote database server has an information disclosure
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of MySQL or MariaDB running on the remote host has a user
enumeration vulnerability.  A remote, unauthenticated attacker could
exploit this to learn the names of valid database users.  This
information could be used to mount further attacks."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Dec/9");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-3909");
  script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("mysql_default_accounts.nbin");
  script_require_ports("Services/mysql", 3306);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("mysql_func.inc");

##
# Sends a MySQL login request that is pretty much guaranteed to fail.
# The resulting error message could be used to fingerprint valid user accounts
#
# @anonparam user username
#
# @return resulting error message, or
#         NULL if anything unexpected happened
##
function _bad_login()
{
  local_var user, login_req, res, err;
  user = _FCT_ANON_ARGS[0];
  login_req =
    '\x8d\x00' +          # client caps
    '\x00\x00\x00' +      # max packet size
    user + '\x00' +       # username
    SCRIPT_NAME + '\x00'; # password

  mysql_send_packet(data:login_req, num:1);
  res = mysql_recv_packet();
  if (isnull(res) || res['len'] < 1)
    return NULL;

  err = mysql_parse_error_packet(packet:res);
  if (strlen(err['msg']) == 0)
    return NULL;

  return err['msg'];
}

# first test a user that is guaranteed to not exist, to make sure
# different error messages are sent in response to bad login attempts
# for nonexistent users
nonexistent_user = strcat(unixtime(), '-', SCRIPT_NAME);
port = get_service(svc:'mysql', default:3306, exit_on_fail:TRUE);
if (supplied_logins_only)  audit(AUDIT_SUPPLIED_LOGINS_ONLY);

mysql_init(port:port, nocache:TRUE, exit_on_fail:TRUE);
err = _bad_login(nonexistent_user);
mysql_close();

if (isnull(err) || 'Access denied' >!< err)
  audit(AUDIT_RESP_BAD, port);

common_users = make_list(
  'root',
  'anonymous',
  'mysql',
  'jeffrey',
  'francis',
  'monty',
  'scrutinizer',
  'scrutremote'
);

# these are default username/password accounts that Nessus has already
# found on the system (mysql_default_accounts.nbin)
default_users = get_kb_list('mysql/' + port + '/user');
if (!isnull(default_users))
{
  known_users = TRUE;
  users = make_list(default_users);
  users = make_list(default_users, common_users);
  users = list_uniq(users);
}
else
{
  known_users = FALSE;
  users = common_users;
}

enumerated_users = make_list();

# then test the list of all valid (or potentially valid) users
# to see if a different error message is sent
foreach user (users)
{
  success = mysql_init(port:port, nocache:TRUE);

  # bailout if the handshake fails _unless_ some usernames have
  # already been enumerated, at which point the plugin will stop
  # making requests and report what it has already found
  if (!success)
  {
    if (max_index(enumerated_users) == 0)
    {
      error = mysql_get_last_error();
      audit_msg =
        'Error connecting to server on port ' + port + ':\n' +
        'Error code: ' +  error['num'] + '\n' +
        'Error message: ' +  error['msg'];
      exit(1, audit_msg);
    }
    else break;
  }

  err = _bad_login(user);
  mysql_close();
  
  if (isnull(err)) continue;
  
  if (
    'Access denied' >!< err &&
    'Client does not support authentication' >< err
  )
  {
    enumerated_users = make_list(enumerated_users, user);
  }
  else if (known_users)
  {
    # if nessus already knows valid usernames, the plugin only needs to see
    # one non-vulnerable response to determine the service is not vulnerable.
    break;
  }
}

if (max_index(enumerated_users) == 0)
  audit(AUDIT_LISTEN_NOT_VULN, 'MySQL', port);

if (report_verbosity > 0)
{
  report =
    '\nNessus was able to enumerate the following MySQL users :\n\n' +
    join(enumerated_users, sep:'\n') + '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);

