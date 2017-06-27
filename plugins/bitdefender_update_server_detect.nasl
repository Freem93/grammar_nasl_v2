#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30020);
  script_version("$Revision: 1.12 $");

  script_name(english:"BitDefender Update Server Detection");
  script_summary(english:"Requests label.dat from various directories");

 script_set_attribute(attribute:"synopsis", value:
"A web server is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote web server is a BitDefender Update Server, used for
centralized updates of BitDefender products on a local network." );
 script_set_attribute(attribute:"see_also", value:"http://www.bitdefender.com/site/Products/" );
 script_set_attribute(attribute:"solution", value:
"N/A" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/01/21");
 script_cvs_date("$Date: 2012/08/23 21:13:31 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:bitdefender:update_server");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2012 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/unknown", 80);

  exit(0);
}



include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") )
{
  port = get_unknown_svc(80);
  if (!port) exit(0, "No unknown service");
  if (silent_service(port)) exit(0, "Service on port "+port+" is 'silent'"); 
}
else port = 80;
if (known_service(port:port)) exit(0, "Service on port "+port+" is known");
if (!get_tcp_port_state(port)) exit(0, "Port "+port+" is closed");


soc = open_sock_tcp(port);
if (!soc) exit(1, "TCP connection refused to port "+port);


# Make a couple of requests.
dirs = make_list(
  "/update_is_90",
  "/update71",
  "/en_fs_24",
  "/en_fs_20"
);

foreach dir (dirs)
{
  res = http_send_recv3(method:"GET", item:string(dir, "/label.dat"), port:port, exit_on_fail: 1);

  # Register and report the service if it looks like the Update Server.
  #
  # nb: Nessus considers the server "broken" because of how
  #     it responds to requests for nonexistent files.
  if (
    "BitDefender Definitions Update" >< res[2] ||
    "BitDefender Product Update" >< res[2]
  )
  {
    register_service(port:port, proto:"www");

    set_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE);
    set_kb_item(name:"www/"+port+"/bitdefender_update_server", value:TRUE);

    security_note(port);
    exit(0);
  }
}
