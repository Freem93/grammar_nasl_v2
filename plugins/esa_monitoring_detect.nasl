#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(22195);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/05/31 21:45:42 $");

  script_name(english:"eIQnetworks Enterprise Security Analyzer Monitoring Agent Detection");
  script_summary(english:"Detects an eIQnetworks Enterprise Security Analyzer Monitoring Agent");

 script_set_attribute(attribute:"synopsis", value:
"A monitoring agent is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a monitoring agent from eIQnetworks
Enterprise Security Analyzer (ESA), a security information and event
management application. 

Note that eIQnetworks Enterprise Security Analyzer is also included in
third-party products such as Astaro Report Manager, Fortinet
FortiReporter, and iPolicy Security Reporter." );
 # http://web.archive.org/web/20070713115713/http://www.eiqnetworks.com/products/EnterpriseSecurityAnalyzer.shtml
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b298df0f" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/08/10");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 10626);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  ) {
  port = get_unknown_svc(10626);
  if ( ! port ) exit(0);
}
else port = 10626;
if (!get_tcp_port_state(port)) exit(0);


# Make sure it looks like the Monitoring Agent.
soc = open_sock_tcp(port);
if (!soc) exit(0);

cmd = string("QUERYMONITOR&nessus&", SCRIPT_NAME, "&&");
send(socket:soc, data:cmd);
res = recv(socket:soc, length:64);
close(soc);


# If it looks like the service...
if (egrep(pattern:"^-~(\^)?Recent (Virus Detections|Emergency Events)$", string:res))
{
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"esa_monitoring");
  security_note(port);
}
