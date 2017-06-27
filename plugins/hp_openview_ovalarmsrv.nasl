#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(19706);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/06/21 21:42:44 $");

  script_name(english:"HP OpenView NNM Alarm Service Detection");
  
 script_set_attribute(attribute:"synopsis", value:
"An HP OpenView Network Node Manager service is listening on this port." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the HP OpenView Network Node Management
Alarm Service.  This service is part of the HP OpenView Management
suite." );
 script_set_attribute(attribute:"solution", value:
"If this service is not needed, disable it or filter incoming traffic
to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/15");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:openview_network_node_manager");
script_end_attributes();

  script_summary(english:"Checks for HP OpenView NNM Alarm Service");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
  script_require_ports(2953,2954);
  exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");

# first port detection


port = 2953;

if (get_port_state(port))
{
 soc = open_sock_tcp (port);
 if (soc)
 {
  data = string("0:0:EVENTS\n");

  send (socket:soc, data:data);
  buf = recv (socket:soc, length:100);

  if (egrep(pattern:"[0-9]:.*:[0-9]+:.*:id:[0-9]+$", string:buf))
  {
   register_service (port:port, proto:"ovalarmsrv");
   security_note(port);
  }
  
  close(soc);
 }
}


# second port detection

port = 2954;

if (!get_port_state(port))
  exit (0);

soc = open_sock_tcp (port);
if (!soc)
  exit (0);

rep = string ("38\n");
data = string("35 4 nessus\n");

send (socket:soc, data:data);
buf = recv (socket:soc, length:4);

if ((strlen(buf) == 3) && (rep >< buf))
{
  register_service (port:port, proto:"ovalarmsrv");
  security_note(port);
}
