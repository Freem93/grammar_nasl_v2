#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78430);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/23 20:52:20 $");

  script_name(english:"ZXShell Malware Services Detection");
  script_summary(english:"Detects the service ports opened by ZXShell.");

  script_set_attribute(attribute:"synopsis", value:"ZXShell is a remote access trojan backdoor.");
  script_set_attribute(attribute:"description", value:
"ZXShell is a remote access trojan backdoor that can be used to persist
on your network for malicious purposes.

Detections : 

  - ZXShell HTTP server 
  - ZXShell Command and Control server");
  # http://www.symantec.com/security_response/writeup.jsp?docid=2014-021716-3303-99
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?12727114");
  script_set_attribute(attribute:"solution", value:"Remove the infection.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");


  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"malware", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Backdoors");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/unknown", 1080, "Services/tcp/socks5", 1985, "Services/www", 80);

  exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

##
#
# !!!!DEACTIVATED BECAUSE OF FALSE POSSITIVE ISSUES!!!!
#
# Detect zxsocks5proxy
# send 05FF0200
# recv 0500
# a normal socks5 service will fail on this
# because the send says FF options but only
# 2 are supplied.
# The malware implements it's own socks5
# server and it hacked together some of the
# protocol and never checks the number of parameters
# field in the send packet.
#
#
# NULL is not detected, list of ports if detected
##
function detect_zxsocks5proxy(test_service_unknown)
{
  local_var soc, port, ports, socks5_ports, zxs_ports, zxs_detected, packet, msg;

  zxs_detected = FALSE;
  zxs_ports = make_list();

  socks5_ports = get_kb_list("Services/tcp/socks5");
  if (test_service_unknown)
    ports = add_port_in_list(list:get_kb_list("Services/unknown"), port:1080);
  else
    ports = make_list(1080);

  if (socks5_ports)
    ports = make_list(ports, socks5_ports);

  packet = raw_string(0x05, 0xFF, 0x02, 0x00);
  foreach port (ports)
  {
    soc = open_sock_tcp(port);
    if (!soc) continue;

    send(socket:soc, data:packet);
    msg = recv(socket:soc, length:1024);

    if (strlen(msg) == 2 && ord(msg[0]) == 5 && ord(msg[1]) == 0)
    {
      zxs_ports = make_list(zxs_ports, port);
      zxs_detected = TRUE;
    }

    close(soc);
  }

  if (zxs_detected)
    return zxs_ports;
  else
    return NULL;
}

function detect_zxhttpserver(test_service_unknown)
{
  local_var res, soc, port, ports, zxs_ports, zxs_detected, packet, msg, http_ports;

  zxs_detected = FALSE;
  zxs_ports = make_list();

  http_ports = get_kb_list("Services/www");
  if (test_service_unknown)
    ports = add_port_in_list(list:get_kb_list("Services/unknown"), port:80);
  else
    ports = make_list(80);

  if (http_ports)
    ports = make_list(ports, http_ports);

  foreach port (ports)
  {
    res = http_send_recv3(
      method       : "GET",
      item         : "/",
      port         : port,
      data         : "",
      transport    : ENCAPS_IP,
      exit_on_fail : FALSE
    );

    if ("ZXHttpServer" >< res[1])
    {
      zxs_ports = make_list(zxs_ports, port);
      zxs_detected = TRUE;
    }
  }

  if (zxs_detected)
    return zxs_ports;
  else
    return NULL;
}

function detect_zxC2server()
{
  local_var res, soc, port, ports, zxs_ports, zxs_detected, packet, msg, http_ports;

  zxs_detected = FALSE;
  zxs_ports = make_list();

  ports = add_port_in_list(list:get_kb_list("Services/unknown"), port:1985);

  packet = raw_string(0x05, 0x02, 0x00);
  foreach port (ports)
  {
    soc = open_sock_tcp(port);
    if (!soc) continue;

    send(socket:soc, data:packet);
    msg = recv(socket:soc, length:1024);

    if ( hexstr(msg) == "85190000250400000000404000000000" )
    {
      zxs_ports = make_list(zxs_ports, port);
      zxs_detected = TRUE;
    }

    close(soc);
  }

  if (zxs_detected)
    return zxs_ports;
  else
    return NULL;
}

os = get_kb_item ("Host/OS/smb") ;
if (isnull(os) || "Windows" >!< os) audit(AUDIT_OS_NOT, "Windows");

test_service_unknown = FALSE;
if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") )
  test_service_unknown = TRUE;

report = '';

zxhttpserv = detect_zxhttpserver(test_service_unknown:test_service_unknown);
if (!isnull(zxhttpserv))
{
  report = 'ZXShell HTTP server detected.';
  foreach zxhs (zxhttpserv)
  {
    register_service(port:zxhs, ipproto:"tcp", proto:"zxshellhttpserver");
    security_hole(port:zxhs, extra:report);
  }
}

zxc2serv = detect_zxC2server();
if (!isnull(zxc2serv))
{
  report = 'ZXShell Command and Control server detected.';
  foreach zxc2 (zxc2serv)
  {
    register_service(port:zxc2, ipproto:"tcp", proto:"zxshellc2");
    security_hole(port:zxc2, extra:report);
  }
}

if (strlen(report) == 0) exit(0, "ZXShell not detected.");
