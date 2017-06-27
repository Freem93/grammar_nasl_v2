#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(46883);
  script_version ("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/04/27 19:46:26 $");

  script_name(english:"Beanstalkd Detection");
  script_summary(english:"Detects Beanstalkd");

  script_set_attribute(attribute:"synopsis", value:
"A messaging server is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"Beanstalkd, a messaging server, is running on the remote
host.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/kr/beanstalkd/wiki");
  # http://nubyonrails.com/articles/about-this-blog-beanstalk-messaging-queue
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c65edc98");
  script_set_attribute(attribute:"see_also", value:"http://github.com/kr/beanstalkd/blob/v1.3/doc/protocol.txt");
  script_set_attribute(attribute:"solution", value:
"If all Beanstalk clients are configured to access the server on the
localhost, consider limiting incoming traffic to this port.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value: "2010/06/14");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");	
  script_family(english:"Service detection");

  script_dependencies("find_service2.nasl");		
  script_require_ports("Services/unknown", 11300);
  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');

if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery"))
{
  port = get_unknown_svc(11300);
  if (!port) exit(0, "There are no unknown services.");
  if (silent_service(port))
    exit(0, "The service on port "+port+" is silent.");
}
else port = 11300;

if (known_service(port:port)) exit(0, "The Service listening on port "+ port + " is already known.");
if (!get_tcp_port_state(port)) exit(1," Port "+ port + " is not open.");

soc = open_sock_tcp(port);
if (!soc) exit(1, "Could not open socket on port "+ port +".");

cmd = "stats";
req =  cmd + '\r\n';

send (socket:soc, data:req);
res = recv (socket:soc, min: 500, length:1024);
close(soc);

if (strlen(res) == 0) exit(1, "The application listening on port " + port + " failed to respond to a 'stats' request.");

if (
  strlen(res) >= 75 && 
  "OK"  >< res && 
  "---" >< res && 
  "current-jobs-urgent:"   >< res &&
  "current-jobs-ready:"    >< res &&
  "current-jobs-reserved:" >< res
)
{
  register_service(port:port, ipproto:"tcp", proto:"beanstalkd");

  if (report_verbosity > 0)
  {
    version = ''; 

    # See if we can extract the version.
    if ('version: ' >< res)
    {
      version = strstr(res,'version: ') - 'version: ' ;
      version = version - strstr(version,'\n');

      if (version =~ "^[0-9.]+$")
        set_kb_item(name:"beanstalkd/"+port+"/version", value:version);
    } 
     
    if (report_verbosity == 1 && version)
      report = '\n'+
        "Beanstalk daemon version "+ version + " is running on the remote host."+
        '\n';  
    else
      report = '\n' +
        'The Beanstalk daemon on the remote host returned the following\n' +
        "information in response to a '"+ cmd + "' command." + '\n\n' +
      res  ;
    security_note(port:port,extra:report);
  } 
  else
    security_note(port);
} 
else exit(0, "Beanstalkd was not detected on port "+ port + ".");
