#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25342);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/04/27 16:06:13 $");

  script_name(english:"XMPP Server Detection");
  script_summary(english:"Attempts to initiate an XMPP session.");

  script_set_attribute(attribute:"synopsis", value:
"An instant messaging server is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"An instant messaging server supporting the Extensible Messaging and
Presence Protocol (XMPP), a protocol used for real-time messaging, is
listening on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.xmpp.org/rfcs/rfc3920.html");
  script_set_attribute(attribute:"solution", value:
"Make sure that the use of this service is in accordance with your
corporate security policy and limit incoming traffic to this port if
desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value: "2007/05/29");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 5222, 5223, 5269);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("xmpp_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") ) 
{
  ports = add_port_in_list(list:get_kb_list("Services/unknown"), port:5222);
}
else ports = make_list(5222);
ports = add_port_in_list(list:ports, port:5223);
ports = add_port_in_list(list:ports, port:5269);
# Zimbra
ports = add_port_in_list(list:ports, port:7335);
ports = add_port_in_list(list:ports, port:10015);
# infinoted
ports = add_port_in_list(list:ports, port:6523);

# Loop through each port.
foreach port (ports)
{
  if (! service_is_unknown(port:port)) continue;
  if (!get_tcp_port_state(port)) continue;

  foreach mode (make_list("client", "server"))
  {
    # Try to start an XMPP session.
    soc = xmpp_open(port:port, mode:mode);
    if (isnull(soc)) continue;

    if (mode == "client")
        register_service(port:port, ipproto:"tcp", proto:"jabber");
    else
        register_service(port:port, ipproto:"tcp", proto:"jabber_s2s");

    report = "The remote XMPP service is used for " + mode + "-to-server communications.";
    security_note(port:port, extra: report);
    break;
  }
}
