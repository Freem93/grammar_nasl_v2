#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38197);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/09/24 16:49:07 $");

  script_cve_id("CVE-2009-1273");
  script_bugtraq_id(34333);
  script_osvdb_id(53693);
  script_xref(name:"Secunia", value:"34536");

  script_name(english:"pam_ssh Login Prompt Remote Username Enumeration");
  script_summary(english:"Checks if the server responds differently to invalid usernames");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running a SSH server with an information
disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a SSH server that responds differently to
login attempts depending on whether or not a valid username is
given. This is likely due to a vulnerable version of pam_ssh.
Other products may be affected as well.

A remote attacker could use this to enumerate valid usernames,
which could be used to mount further attacks."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.gentoo.org/show_bug.cgi?id=263579"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Contact the vendor for a fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(255);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
  script_require_ports("Services/ssh", 22);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");

port = get_service(svc:'ssh', exit_on_fail:TRUE, default:22);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

function setup_ssh()
{
  local_var server_version, ret, payload;

  # Exchange protocol version identification strings with the server.
  init();
  server_version = ssh_exchange_identification();
  if (!server_version) exit(1, "Could not contact the remote SSH server on port " + port);

  _ssh_server_version = server_version;

  # key exchange
  ret = ssh_kex2(server_version:server_version, nofingerprint:TRUE);
  if (ret != 0) exit(1, "Could not contact the remote SSH server on port " + port);
  payload = putstring(buffer:"ssh-userauth");

  # code 5 (SSH_MSG_SERVICE_REQUEST)
  send_ssh_packet(payload:payload, code:raw_string(0x05));

  # code 6 (SSH_MSG_SERVICE_ACCEPT)
  payload = recv_ssh_packet();

  # Bail out if the server doesn't support the ssh-userauth service
  # (it's required in order to do the check in this plugin)
  if (ord(payload[0]) != 6) exit(1, "Could not contact the remote SSH server on port " + port + " (protocol error)");
}



# Sends a SSH_MSG_USERAUTH_REQUEST and gets the response
#
function get_userauth_req_resp(user)
{
  local_var payload, response_code, buf, num, next;
  response_code = NULL;

  if( ! get_port_state(port) ) exit(0, "No SSH server");
  _ssh_socket = open_sock_tcp(port);
 if ( ! _ssh_socket ) exit(0, "No SSH server");
  setup_ssh();

 payload = putstring(buffer:"ssh-userauth");

 # code 5 (SSH_MSG_SERVICE_REQUEST)
 send_ssh_packet(payload:payload, code:raw_string(0x05));
 payload = recv_ssh_packet();
 if (ord(payload[0]) != 6) exit(1, "Could not contact the remote SSH server on port " + port + " (protocol error)");



 payload = putstring(buffer:user) +
           putstring(buffer:"ssh-connection") +
           putstring(buffer:"none");
 send_ssh_packet(payload:payload, code:raw_int8(i:50));
 payload = recv_ssh_packet();

 if ( ord(payload[0]) != 51 ) exit(1, "Could not contact the remote SSH server on port " + port + " (protocol error)");

 if ( 'keyboard-interactive' >!< getstring(buffer:payload, pos:1)) 
	exit(0, "No keyboard-interactive method - server is not affected");

  # send...
  payload = strcat(
    putstring(buffer:user),
    putstring(buffer:"ssh-connection"),
    putstring(buffer:"keyboard-interactive"),
    putstring(buffer:"en-US"),
    putstring(buffer:"")
  );

  send_ssh_packet(payload:payload, code:raw_int8(i:50));

  # ... and check response
  payload = recv_ssh_packet();
  if (isnull(payload)) exit(1, "Could not contact the remote SSH server on port " + port + " (protocol error)");

  response_code = ord(payload[0]);
  if ( response_code != 60 ) exit(1, "Could not contact the remote SSH server on port " + port + " (protocol error)");

  # Method name
  buf = getstring (buffer:payload,pos:1);
  next = 1 + 4 + strlen(buf);

  # Method name complement
  buf = getstring (buffer:payload,pos:next);
  next = next + 4 + strlen(buf);

  # Language
  buf = getstring (buffer:payload,pos:next);
  next = next + 4 + strlen(buf);

  num = ntol(buffer:payload, begin:next);
  next += 4;

  if ( num <= 0 ) exit(1, "Could not contact the remote SSH server on port " + port + " (protocol error)");
  buf = getstring (buffer:payload,pos:next);



  close(_ssh_socket);
  
  return buf;
}


#
# Script execution starts here
#

valid_user_resp = get_userauth_req_resp(user:"root");
if ( isnull(valid_user_resp) ) exit(0, "Unknown error");
if ( valid_user_resp != 'SSH passphrase: ' ) audit(AUDIT_HOST_NOT, 'affected');

rand_user = rand_str(length:8);
invalid_user_resp = get_userauth_req_resp(user:rand_user);
if ( isnull(invalid_user_resp) ) exit(0, "Unknown error");

if ( invalid_user_resp == 'SSH passphrase: ' ) audit(AUDIT_HOST_NOT, 'affected');

if (report_verbosity > 0)
{
  report = 
    '\nTrying to log in as \'root\' returns the following password prompt :' +
    '\n\n  "' + valid_user_resp + '"' +
    '\nwhile trying to log in as \'' + rand_user + '\' returns the following' +
    ' password prompt :\n\n' + 
    '  "' + invalid_user_resp + '"';
  security_warning(port:port, extra:report);
}
else security_warning(port);
exit(0);
