#
# Copyright (C) 2004 Tenable Network Security
#


include("compat.inc");

if(description)
{
  script_id(12115);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2011/03/17 11:28:56 $");

  script_name(english:"Unreal Tournament Server Detection");

 script_set_attribute(attribute:"synopsis", value:
"A game server appears to be running on the remote system." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Unreal Tournament 
Server. The Server is used to host Internet and Local Area 
Network (LAN) games." );
 script_set_attribute(attribute:"solution", value:
"Ensure that this sort of network gaming is in alignment
with Corporate and Security Policies." );
 script_set_attribute(attribute:"risk_factor", value:"None" );


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/03/23");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  summary["english"] = "Detects Unreal Tournament Server";
  script_summary(english:summary["english"]);
  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");

  script_family(english:"Service detection");
  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


# start script
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!port) exit(0);

banner = get_http_banner(port:port);
if(!banner)exit(0);

if (egrep(string:banner, pattern:"^Server: UnrealEngine UWeb Web Server Build")) security_note(port); 
