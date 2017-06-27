#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77606);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/09/10 19:30:57 $");

  script_bugtraq_id(68426);
  script_osvdb_id(108797);

  script_name(english:"SYAC DigiEye Backdoor Detection");
  script_summary(english:"Detects the SYAC/Techboard DigiEye port 7339 backdoor.");

  script_set_attribute(attribute:"synopsis", value:"The remote device contains a backdoor.");
  script_set_attribute(attribute:"description", value:
"The remote device is a SYAC DigiEye, a digital video recorder, with a
backdoor running on port 7339. An attacker can use the backdoor to run
arbitrary commands or access configuration details (including
passwords) on the device, with administrative (root) privileges.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2014/Jul/17");
  script_set_attribute(attribute:"see_also", value:"http://blog.emaze.net/2014/07/backdoor-techboardsyac.html");
  script_set_attribute(attribute:"see_also", value:"http://www.syac-tb.com/en/products/digital-video-recorders/digieye-3g");
  script_set_attribute(attribute:"solution", value:"Contact the device vendor regarding the availability of an update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:syac:digieye");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Backdoors");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports(7339);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("dump.inc");

port = 7339;
if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
if (known_service(port:port)) audit(AUDIT_SVC_ALREADY_KNOWN, port);
if (silent_service(port)) audit(AUDIT_SVC_SILENT, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

req = "KNOCK-KNOCK-ANYONETHERE?" + raw_string(0x00);
send(socket:soc, data:req);

resp = recv(socket:soc, length:12);
close(soc);

if (strlen(resp) < 12) audit(AUDIT_RESP_BAD, port, "SYAC DigiEye Backdoor probe", "TCP");

magic = getdword(blob:resp, pos:8);
if (magic != 0x000aae60) audit(AUDIT_NOT_DETECT, "SYAC DigiEye Backdoor", port);

register_service(port:port, proto:'syac_digieye_backdoor');
if (report_verbosity > 0)
{
  report = 
    '\n' + 'Nessus verified the remote backdoor by sending this request :' +
    '\n' + 
    '\n' + hexdump(ddata:req) + 
    '\n' + 'and receiving this response :' +
    '\n' + 
    '\n' + hexdump(ddata:resp);
  security_hole(port:port, extra:report);
}
else security_hole(port);
