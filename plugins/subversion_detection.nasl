#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(12259);
 script_version ("$Revision: 1.6 $");
 script_cvs_date("$Date: 2011/03/11 21:52:40 $");

 script_name(english:"Subversion Server Detection");

  script_set_attribute(attribute:"synopsis", value:
"A version control software is installed on the remote host." );

 script_set_attribute(attribute:"description", value:
"The remote host is running the Subversion server.  Subversion
is a software product which is similar to CVS in that it manages
file revisions and can be accessed across a network by multiple
clients." );

  script_set_attribute(attribute:"see_also", value:"http://subversion.tigris.org" );
  script_set_attribute(
    attribute:"solution",
    value:
"If this server is not needed, disable it or filter incoming traffic
to this port.");

  script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/06/08");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 script_summary(english:"Subversion Detection");

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_dependencie("find_service2.nasl");
 script_require_ports(3690,"Services/unknown");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

if (thorough_tests &&
  ! get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(3690);
  if (!port) exit(0);
  if (!silent_service(port)) exit(0);
}
else 
{
  port = get_kb_item("Services/subversion");
  if ( ! port ) port = 3690;
}

if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);

# start check

soc = open_sock_tcp(port);
if (!soc)
        exit(0);

r = recv_line(socket:soc, length:1024);

if (! r)
	exit(0);

if (("success ( 1 2" >< r) || 
    ("success ( 2 2" >< r))
	security_note(port);

close(soc);
exit(0);
