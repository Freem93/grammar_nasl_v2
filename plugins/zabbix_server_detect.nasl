#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22526);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/06/20 20:29:03 $");

  script_name(english:"Zabbix Server Detection");
  script_summary(english:"Detects a Zabbix server");

  script_set_attribute(attribute:"synopsis", value:"A Zabbix server is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a Zabbix server.  Zabbix is an open source
network monitoring application, and a Zabbix server is used to collect
information from agents on hosts being monitored.");
  script_set_attribute(attribute:"see_also", value:"http://www.zabbix.com/");
  script_set_attribute(attribute:"solution", value:"Limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value: "cpe:/a:zabbix:zabbix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 10051);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  )
{
  port = get_unknown_svc(10051);
  if (!port) exit(0);
}
else port = 10051;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Simulate a connection from an agent.
req = string("ZBX_GET_ACTIVE_CHECKS\n", SCRIPT_NAME, "-", unixtime());
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);
close(soc);


# It's a Zabbix server if the response is "ZBX_EOF".
if (res && res == 'ZBX_EOF\n')
{
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"zabbix_server");

  security_note(port);
}
