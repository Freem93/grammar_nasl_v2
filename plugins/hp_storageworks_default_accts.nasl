#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51418);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2015/10/13 15:19:32 $");

  script_cve_id("CVE-2012-0697");
  script_bugtraq_id(51399);
  script_osvdb_id(78308);

  script_name(english:"HP StorageWorks MSA P2000 Default Credentials");
  script_summary(english:"Tries to login using a default account");

  script_set_attribute(attribute:"synopsis", value:
"The remote device has one or more accounts that use default
credentials.");
  script_set_attribute(attribute:"description", value:
"The remote device appears to be an HP StorageWorks MSA P2000 series.
One or more accounts are secured with a default password. A remote,
unauthenticated attacker can exploit this to gain administrative
access to the management interface.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-015/");
  script_set_attribute(attribute:"solution", value:"Secure all accounts with a strong password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:storageworks");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl", "telnet.nasl", "ftpserver_detect_type_nd_version.nasl", "DDI_FTP_Any_User_Login.nasl", "ftp_anonymous.nasl", "account_check.nasl");
  script_require_ports("Services/ssh", 22, "Services/telnet", 23, "Services/ftp", 21);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("http.inc");
include("ftp_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

LOGIN_SUCCESS = 0;
LOGIN_FAILED = -1;
PORT_CLOSED = -2;
CONNECTION_FAILED = -3;
NO_PROMPT = -4;
NO_RESPONSE = -5;

global_var reports, errors, err_code;

reports = make_array();
errors = '';
err_code = 1;

function get_error_msg(code, port)
{
  if (code == LOGIN_FAILED)
    return 'The login attempt on port '+port+' failed.';
  else if (code == PORT_CLOSED)
    return 'Port '+port+' is not open.';
  else if (code == CONNECTION_FAILED)
    return 'Failed to open a socket on port '+port+'.';
  else if (code == NO_PROMPT)
    return 'Unable to get telnet prompt from port '+port+'.';
  else if (code == NO_RESPONSE)
    return 'The service on port '+port+' failed to respond.';
  else
    return 'Unexpected error on port '+port+'.';
}

function report_add()
{
  local_var user, pass, port;
  user = _FCT_ANON_ARGS[0];
  pass = _FCT_ANON_ARGS[1];
  port = _FCT_ANON_ARGS[2];

  reports[port] +=   # global
    '\n  Username : ' + user +
    '\n  Password : ' + pass + '\n';

  if (!thorough_tests)
  {
    if (report_verbosity > 0)
    {
      reports[port] +=
        '\nNessus stopped after the first successful login. There may be'+
        '\nadditional accounts secured with a default password. Enable'+
        '\nthe \'Perform thorough tests\' setting and re-scan to check for all'+
        '\ndefault accounts.\n';
      security_hole(port:port, extra:reports[port]);
    }
    else
      security_hole(port);
    exit(0);
  }
}

function check_ssh(port, login, password)
{
  local_var soc, res, line, payload, remote_channel;
  if (!get_port_state(port)) return PORT_CLOSED;
  # Prevent a FP
  if ( get_kb_item("login/auth/broken") || get_kb_item("login/unix/auth/broken" ) ) return PORT_CLOSED;

  _ssh_socket = open_sock_tcp(port);
  if ( !_ssh_socket ) return CONNECTION_FAILED;

  res = ssh_login(login:login, password:password);

  if (res == LOGIN_SUCCESS)
  {
    # taken from default_account.inc
    #
    # Some SSH servers do not fully respect the SSH protocol - they
    # claim that password authentication succeeded, but then
    # they'll refuse any other command. The workaround here is to
    # open a SSH, as if we wanted to create an interactive session.
    #
    # Note that we do not use ssh_open_channel() but a stripped down version
    #
    payload = putstring(buffer:"session") + raw_int32(i:1) + raw_int32(i:32768) + raw_int32(i:32768);
    send_ssh_packet(payload:payload, code:raw_int8(i:90));
    payload = recv_ssh_packet();
    if ( !isnull(payload) )
    {
      # Fix for tectia AIX
      if (ord(payload[0]) == 95)
      {
        payload = getstring(buffer:payload, pos:9);
        payload = recv_ssh_packet();
      }
      if ( !isnull(payload) && ord(payload[0]) == 91 )
      {
        remote_channel = ntol(buffer:payload, begin:5);
        payload = raw_int32(i:remote_channel) + putstring(buffer:"pty-req") + raw_int8(i:0) +
        putstring(buffer:"vt100") + raw_int32(i:80) + raw_int32(i:24) + raw_int32(i:640) + raw_int32(i:480) +
        putstring(buffer:
                             raw_int8(i:53) + raw_int32(i:0) +
                             raw_int8(i:72) + raw_int32(i:0) +
                             raw_int8(i:0));

        # SSH_MSG_CHANNEL_REQUEST == 98
        send_ssh_packet(payload:payload, code:raw_int8(i:98));
        payload = raw_int32(i:remote_channel) + putstring(buffer:"shell") + raw_int8(i:0) ;
        # SSH_MSG_CHANNEL_REQUEST == 98
        send_ssh_packet(payload:payload, code:raw_int8(i:98));
        payload = raw_int32(i:remote_channel) + putstring(buffer:'\n');
        send_ssh_packet(payload:payload, code:raw_int8(i:94));
        payload = recv_ssh_packet();

        if ( !isnull(payload) && ord(payload[0]) == 94 )
        {
          payload = getstring(buffer:payload, pos:5);
          # avoid false positives, such as with Infoblox
          if (
            "Domain (? for all)" >!< payload && 
            "invalid login" >!< payload &&
            ("ogin:" >!< payload || "Last login: " >< payload) && 
            "User Name:" >!< payload &&
            "assword:" >!< payload
          )  
          {
            set_kb_blob(name:"hp_storageworks/"+port+"/payload", value:payload);
            ssh_close_connection();
            report_add(login, password, port);
            return LOGIN_SUCCESS;
          }
        }
      }
    }
  }

  ssh_close_connection();

  err_code = 0;  # we know for sure the login attempt failed

  # when thorough is enabled, recurse, trying 'hpinvent' (another common password)
  if (thorough_tests && password != 'hpinvent')
    return check_ssh(port:port, login:login, password:'hpinvent');

  return LOGIN_FAILED;
}

function check_telnet(port, login, password)
{
  local_var soc, res, line;
  if (!get_port_state(port)) return PORT_CLOSED;

  soc = open_sock_tcp(port);
  if(!soc) return CONNECTION_FAILED;

  res = telnet_negotiate(socket:soc);
  res += recv_until(socket:soc, pattern:"login:");
  if (!res) return NO_PROMPT;

  send(socket:soc, data:login + '\r\n');
  res = recv_until(socket:soc, pattern:"Password:");
  if (isnull(res))
  {
    close(soc);
    return NO_RESPONSE;
  }

  send(socket:soc, data:password + '\r\n');
  res = recv(socket:soc, length:256);
  close(soc);

  if (isnull(res)) return NO_RESPONSE;

  if ('HP StorageWorks' >< res)
  {
    report_add(login, password, port);
    return LOGIN_SUCCESS;
  }
  else
  {
    err_code = 0;  # we know for sure the login attempt failed

    # when thorough is enabled, recurse, trying 'hpinvent' (another common password)
    if (thorough_tests && password != 'hpinvent')
      return check_telnet(port:port, login:login, password:'hpinvent');
    else
      return LOGIN_FAILED;
  }
}

function check_ftp(port, login, password)
{
  local_var soc, res, line;
  if (!get_port_state(port)) return PORT_CLOSED;

  soc = open_sock_tcp(port);
  if(!soc) return CONNECTION_FAILED;

  res = ftp_authenticate(socket:soc, user:login, pass:password);
  close(soc);

  if (res)
  {
    report_add(login, password, port);
    return LOGIN_SUCCESS;
  }
  else
  {
    err_code = 0;  # we know for sure the login attempt failed

    # when thorough is enabled, recurse, trying 'hpinvent' (another common password)
    if (thorough_tests && password != 'hpinvent')
      return check_ftp(port:port, login:login, password:'hpinvent');
    else
      return LOGIN_FAILED;
  }
}

# Check if each service was detected, and fall back to the
# well known ports by default
ssh_port = 22;
ssh_ports = get_kb_list('Services/ssh');
if (!isnull(ssh_ports))
{
  ssh_ports = make_list(ssh_ports);
  ssh_port = ssh_ports[0];
}

# in case we add the web login in one day...
#web_port = 80;
#web_ports = get_kb_list('Services/www');
#if (!isnull(web_ports))
#{
#  foreach port (web_ports)
#  {
#    # There's a broken webserver that listens by default on
#    # TCP 5989 (WBEM over HTTPS?) which we don't want to test
#    if (!http_is_broken(port:port))
#    {
#      web_port = port;
#      break;
#    }
#  }
#}

telnet_port = 23;
telnet_ports = get_kb_list('Services/telnet');
if (!isnull(telnet_ports))
{
  telnet_ports = make_list(telnet_ports);
  telnet_port = telnet_ports[0];
}

ftp_port = 21;
ftp_ports = get_kb_list('Services/ftp');
if (!isnull(ftp_ports))
{
  ftp_ports = make_list(ftp_ports);
  ftp_port = ftp_ports[0];
}

# For each subsequent login attempt, we only want to try to
# login to services that we know are listening
skip_ssh = FALSE;
skip_telnet = FALSE;
skip_ftp = FALSE;

# Avoid the possibility of testing a FTP server that accepts
# any username and password
if (
  get_kb_item('ftp/' + ftp_port + '/broken') ||
  get_kb_item('ftp/' + ftp_port + '/backdoor') ||
  get_kb_item('ftp/' + ftp_port + '/anonymous') ||
  get_kb_item('ftp/' + ftp_port + '/AnyUser')
)
{
  skip_ftp = TRUE;
}

accts = make_array(
  'manage', '!manage',
  'monitor', '!monitor',
  'ftp', '!ftp'
);

# Attempt to login as each account for SSH, telnet, and FTP.
# The plugin will try to use the same service for each login
# attempt, and will only move on to the next service if a
# login fails for any reason other than invalid credentials
foreach user (keys(accts))
{
  pass = accts[user];

  if (!skip_ssh)
  {
    ret = check_ssh(port:ssh_port, login:user, password:pass);
    if (ret != LOGIN_SUCCESS)
    {
      errors += get_error_msg(code:ret, port:ssh_port) + ' ';  # global
      if (ret != LOGIN_FAILED) skip_ssh = TRUE;
    }
  }

  if (skip_ssh && !skip_telnet)
  {
    ret = check_telnet(port:telnet_port, login:user, password:pass);
    if (ret != LOGIN_SUCCESS)
    {
      errors += get_error_msg(code:ret, port:telnet_port) + ' ';  # global
      if (ret != LOGIN_FAILED) skip_telnet = TRUE;
    }
  }

  if (skip_telnet && !skip_ftp)
  {
    ret = check_ftp(port:ftp_port, login:user, password:pass);
    if (ret != LOGIN_SUCCESS)
    {
      errors += get_error_msg(code:ret, port:ftp_port) + ' ';  # global
      if (ret != LOGIN_FAILED) skip_ftp = TRUE;
    }
  }
}

if (skip_ssh && skip_telnet && skip_ftp)
  errors = 'none of the services (SSH, telnet, FTP) were suitable for testing.';

ports = keys(reports);
if (max_index(ports) == 0)
  exit(err_code, 'Default logins failed due to : ' + errors);

foreach port (ports)
{
  if (report_verbosity > 0)
  {
    report = reports[port];
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
