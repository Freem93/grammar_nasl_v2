#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19758);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2011/03/11 21:52:40 $");

  script_name(english:"Tofu Server Detection");
  script_summary(english:"Detects Tofu servers");

 script_set_attribute(attribute:"synopsis", value:
"A game server is installed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a Tofu server.  Tofu is a network gaming
engine. Make sure this service has been installed in accordance to your
security policy." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2cfee080" );
 script_set_attribute(attribute:"solution", value:
"If this service is not needed, disable it or filter incoming traffic
to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/19");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");

  script_require_ports("Services/unknown", 6900);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  ) {
  port = get_unknown_svc(6900);
  if ( ! port ) exit(0);
}
else port = 6900;
if (!get_port_state(port)) exit(0);


# Try to login to the Tofu server.
soc = open_sock_tcp(port);
if (!soc) exit(0);

pkt_login = raw_string(
  ">", 
  SCRIPT_NAME,
   "\n",
  "nessus",
  "\n"
);
c = string(strlen(pkt_login), ":", pkt_login, ",");
send(socket:soc, data:c);

s = recv(socket:soc, length:1024);
if (!strlen(s)) exit(0);


# There's a if it looks like we're logged in.
len = s - strstr(s, ":");
i = strlen(len);
j = i + int(len) + 1;
if (
  # it looks like a valid Tofu packet and ...
  (i > 0 && strlen(s) > i && strlen(s) > j &&  s[i] == ':' && j > i && s[j] == ',') && 
  # it looks like we're logged in.
  "_reconstructor" >< s
) {
  security_note(port);

  register_service(port:port, ipproto:"tcp", proto:"tofu");
}
