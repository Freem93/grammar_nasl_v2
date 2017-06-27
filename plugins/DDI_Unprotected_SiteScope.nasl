#
# This script was written by H D Moore
# 

# Changes by Tenable:
# - Revised plugin title (4/9/2009)

include("compat.inc");

if(description)
{
    script_id(10778);
    script_version ("$Revision: 1.26 $");
    script_cvs_date("$Date: 2012/08/15 21:05:11 $");

    script_cve_id("CVE-1999-0508");
    script_osvdb_id(649);

    script_name(english:"SiteScope Web Service Unpassworded Access");
    script_summary(english:"Unprotected SiteScope Service");

    script_set_attribute(attribute:"synopsis", value:
"The remote administrative web server does have a password.");
    script_set_attribute(attribute:"description", value:
"The remote SiteScope web service has no password set.  An attacker who
can connect to this server can view usernames and passwords stored in
the preferences section or reconfigure the service.");
    script_set_attribute(attribute:"solution", value:
"Make sure that a password is set in the configuration for this
service.  Depending on where this server is located, you may want to
restrict access by IP address in addition to username.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SNMP Community Scanner');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
    script_set_attribute(attribute:"plugin_publication_date", value:
"2001/09/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/04/14");
    script_set_attribute(attribute:"plugin_type", value:"remote");
    script_end_attributes();

    script_category(ACT_ATTACK);

    script_copyright(english:"This script is Copyright (C) 2001-2012 Digital Defense Inc.");

    script_family(english:"CGI abuses");
    script_dependencie("find_service1.nasl", "http_version.nasl");
    script_require_ports("Services/www", 8888);
    
    exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


function sendrequest (request, port)
{
    local_var reply;

    reply = http_keepalive_send_recv(port: port, data:request);
    if ( isnull(reply) ) exit(0);
    else return reply;
}

#
# The script code starts here
#


ports = add_port_in_list(list:get_kb_list("Services/www"), port:8888);
foreach port (ports)
{
 req = http_get(item:"/SiteScope/cgi/go.exe/SiteScope?page=eventLog&machine=&logName=System&account=administrator", port:port);
 reply = sendrequest(request:req, port:port);

 if ("Event Log" >< reply && 
     "<FORM ACTION=/SiteScope/cgi/go.exe/SiteScope method=POST>" >< reply &&
     "<input type=hidden name=page value=eventLog>" >< reply )
 {
    security_hole(port:port);
 }
}
