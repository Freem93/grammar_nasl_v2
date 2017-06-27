#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86122);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/03/21 20:50:54 $");

  script_cve_id("CVE-2015-5600");
  script_bugtraq_id(75990);
  script_osvdb_id(124938);

  script_name(english:"OpenSSH MaxAuthTries Bypass");
  script_summary(english:"Attempts to bypass MaxAuthTries to allow password brute-force attack.");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by a security
bypass vulnerability that allows password brute-force attacks.");
  script_set_attribute(attribute:"description", value:
"The remote SSH server is affected by a security bypass vulnerability
due to a flaw in the keyboard-interactive authentication mechanisms.
The kbdint_next_device() function in auth2-chall.c improperly
restricts the processing of keyboard-interactive devices within a
single connection. A remote attacker can exploit this, via a crafted
keyboard-interactive 'devices' string, to bypass the normal
restriction of 6 login attempts (MaxAuthTries), resulting in the
ability to conduct a brute-force attack or cause a denial of service
condition.");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-7.0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 7.0 or later.

Alternatively, this vulnerability can be mitigated on some Linux
distributions by disabling the keyboard-interactive authentication
method. This can be done on Red Hat Linux by setting
'ChallengeResponseAuthentication' to 'no' in the /etc/ssh/sshd_config
configuration file and restarting the sshd service.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh");
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");

global_var ERR_AUTH_SUCCESS, ERR_PASSWORD_CHANGE, ERR_PASSWORD_NOT_SUPP;

ERR_AUTH_SUCCESS = 0;
ERR_PASSWORD_CHANGE = -1;
ERR_PASSWORD_NOT_SUPP = -2;

function rand_auth()
{
  return 'nessus_' + rand_str(length:8, charset:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
}

##
# Attempts MaxAuthTries Brute-force via SSHv2 authentication using the keyboard interactive method
#
# @remark See RFC 4256 for details of keyboard-interactive auth.
#
# @param password Password to attempt to log in with.
# @param user Username to attempt to log in with.
# @param submethods Optional comma-separated list of authentication submethods
#
# @return number of attempts or <= 0 for error.
##
function ssh_auth_keyboard_bruteforce(password, user, submethods, port)
{
  local_var attempts, code, crap, kb_ok, next, payload, prompt, prompts, res, inst;

  if (isnull(submethods)) submethods = "";
  if (isnull(password) || password == "") password = rand_auth(); 

  # Request keyboard-interactive authentication from the server.
  payload =
    putstring(buffer:user) +
    putstring(buffer:"ssh-connection") +
    putstring(buffer:"keyboard-interactive") +
    putstring(buffer:"en-US") +
    putstring(buffer:submethods);

  send_ssh_packet(code:SSH_MSG_USERAUTH_REQUEST, payload:payload);

  # Read the server's response.
  res = recv_ssh_packet();
  code = ord(res[0]);
  next = 1;

  if (code == SSH_MSG_USERAUTH_FAILURE)
  {
    # Not vuln
    return 1;
  }

  if (code == SSH_MSG_UNIMPLEMENTED)
  {
    # Doesn't support SSH_MSG_USERAUTH_REQUEST so doesn't support keyboard-interactive.
    ssh_close_connection();
    exit(0, "The SSH service listening on port "+port+" does not support 'keyboard-interactive' authentication.");
  }

  if (code != SSH_MSG_USERAUTH_INFO_REQUEST)
  {
    ssh_close_connection();
    exit(1, "Server did not reply with SSH_MSG_USERAUTH_INFO_REQUEST during"+'\n'+"keyboard-interactive exchange. It replied with : " + code + ".");
  }

  # Skip over name.
  crap = getstring(buffer:res, pos:next);
  next += 4 + strlen(crap);

  # Skip over instruction.
  inst = getstring(buffer:res, pos:next);
  next += 4 + strlen(inst);

  # Skip over language.
  crap = getstring(buffer:res, pos:next);
  next += 4 + strlen(crap);

  # Parse number of prompts.
  prompts = ntol(buffer:res, begin:next);
  next += 4;

  kb_ok = FALSE;
  if (prompts > 0)
  {
    prompt = getstring(buffer:res, pos:next);
    #
    # nb: Alcatel OS switches have a bug in their SSH server which make the prompt be a single space.
    if (
      buffer_contains_password_prompt(prompt, user) ||
      "'s password for keyboard-interactive method:" >< inst
    )
    {
      if  ( "'s password for keyboard-interactive method:" >< inst && prompt == " ") AOS_SSH = TRUE;
      kb_ok = TRUE;
    }
  }

  if (!kb_ok)
  {
    return ERR_PASSWORD_NOT_SUPP;
  }

  attempts = 1;
  # Put limit on attempts to be sure this loop will exit.
  while (attempts <= 50)
  {
    # Send a single response, containing the password, to server.
    SSH_PACKET_LOG_SCRUB_STRING = password;
    payload = raw_int32(i:1) + putstring(buffer:password);
    send_ssh_packet(code:SSH_MSG_USERAUTH_INFO_RESPONSE, payload:payload);
    SSH_PACKET_LOG_SCRUB_STRING = FALSE;

    # Read response from server.
    res = recv_ssh_packet();
    code = ord(res[0]);
    if (code == SSH_MSG_USERAUTH_INFO_REQUEST)
    {
      if (
        "Changing password for " >< res ||                    # HPUX
        "Password change requested" >< res ||                 # SuSE 10
        "Password changing requested" >< res ||               # SuSE 9
        "Your password has expired" >< res ||                 # Solaris
        "New Password" >< res ||                              # FreeBSD
        "You are required to change your password" >< res     # Gentoo
      )
      {
        return ERR_PASSWORD_CHANGE;
      }
    }
    else if (code == SSH_MSG_USERAUTH_SUCCESS)
    {
      # Auth succeeded this shouldn't happen.
      return ERR_AUTH_SUCCESS;
    }
    else
    {
      break;
    }

    attempts += 1;
  }

  return attempts;
}

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Bad username/password
user = rand_auth();
password = rand_auth();

port = get_service(svc:"ssh", exit_on_fail:TRUE);

_ssh_socket = open_sock_tcp(port);
if (!_ssh_socket) audit(AUDIT_SOCK_FAIL, port);

# initialization
init();
server_version = ssh_exchange_identification();
if (!server_version)
{
  ssh_close_connection();
  exit(1, get_ssh_error());
}

_ssh_server_version = server_version;

# key exchange
ret = ssh_kex2(server_version:server_version, nofingerprint:TRUE);
if (ret != 0)
{
  ssh_close_connection();
  exit(1, get_ssh_error());
}

if (!ssh_req_svc("ssh-userauth"))
{
  ssh_close_connection();
  exit(0, "The SSH service listening on port "+port+" does not support 'ssh-userauth'.");
}

if (!ssh_auth_supported(method:"keyboard-interactive", user:user))
{
  ssh_close_connection();
  exit(0, "The SSH service listening on port "+port+" does not support 'keyboard-interactive' authentication.");
}

vuln = FALSE;
attempts = -1;
# Try an attempt with no devices set followed by one with 2 set.
# First attempt checks normal attempt and sets attempts baseline.
# Second attempt should see an increase matching the number of devices.
#  In this case two.
# If an increase in attempts that matches the number of devices passed is
#  detected then the openssh service is vulnerable.
for (i=0; i < 3; i+=2)
{
  prev_attempts = attempts;
  submethods = crap(data:"p,", length:i*2);
  attempts = ssh_auth_keyboard_bruteforce(user:user, password:password, submethods:submethods, port:port);
  if (attempts == ERR_PASSWORD_CHANGE)
  {
    ssh_close_connection();
    exit(1, "Couldn't determine, target requested password change.");
  }
  else if (attempts == ERR_AUTH_SUCCESS)
  {
    ssh_close_connection();
    exit(1, "Couldn't determine, authentication with account " + user + " succeeded.");
  }
  else if (attempts == ERR_PASSWORD_NOT_SUPP)
  {
    # Not vuln
    break;
  }
  else if (attempts == i && attempts > prev_attempts)
  {
    vuln = TRUE;
    break;
  }
}

ssh_close_connection();

if (vuln)
{
  security_hole(port:port);
}
else
{
  audit(AUDIT_LISTEN_NOT_VULN, "SSH", port);
}
