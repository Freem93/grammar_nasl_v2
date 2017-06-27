#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25037);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/05/26 16:06:48 $");

  script_name(english:"Printer Job Language (PJL) Detection");
  script_summary(english:"Talks PJL to HP JetDirect service.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host uses the PJL protocol.");
  script_set_attribute(attribute:"description", value:
"Nessus had detected that the service running on the remote host will
answer an HP Printer Job Language (PJL) request, which indicates that
it is a printer device running HP JetDirect. By using the PJL
protocol, users can submit printing jobs, transfer files to or from
the printer, and change configuration settings.");
  script_set_attribute(attribute:"see_also", value:"http://www.maths.usyd.edu.au/u/psz/ps.html");
  # https://web.archive.org/web/20070312205453/http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=bpl04568
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92cb3210");
  script_set_attribute(attribute:"see_also", value:"http://h10032.www1.hp.com/ctg/Manual/bpl13208");
  script_set_attribute(attribute:"see_also", value:"http://h10032.www1.hp.com/ctg/Manual/bpl13207");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value: "None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_require_ports(9100, "Services/unknown");
  script_require_keys("Scan/Do_Scan_Printers");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Scan/Do_Scan_Printers"))
{
  exit(0, "Printer scanning is disabled");
}

ports = make_list(9100);
if (thorough_tests)
{
  ports = get_kb_list("Services/unknown");
  ports = add_port_in_list(list:ports, port:9100);
}

foreach port (ports)
{
  if (known_service(port:port) || !get_tcp_port_state(port)) continue;

  s = open_sock_tcp(port);
  if (!s) continue;

  # send a basic info request
  send(socket: s, data: '\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X\r\n');
  r = recv(socket: s, length: 1024);
  close(s);

  # validate the response is PJL
  if (isnull(r) || '@PJL INFO ID\r\n' >!< r) continue;

  # Carve out the device info that was sent
  info = NULL;
  lines = split(r, keep: 0);
  if (max_index(lines) >= 1 && strlen(lines[1]) > 0)
  {
    info = ereg_replace(string: lines[1], pattern: '^ *"(.*)" *$', replace: "\1");
    if (strlen(info) == 0) info = lines[1];
    set_kb_item(name:'jetdirect/' + port + '/info', value:lines[1]);
    info = '\nThe device INFO ID is:\n\n' + info + '\n';
  }

  security_report_v4(port: port, severity:SECURITY_NOTE, extra:info);
  register_service(port:port, proto:'jetdirect');
  set_kb_item(name: 'devices/hp_printer', value: TRUE);
}
