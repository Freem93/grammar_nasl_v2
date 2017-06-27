#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14837);
 script_version ("$Revision: 1.15 $");
 script_bugtraq_id(11253);
 script_osvdb_id(52981, 52982, 52983);

 script_name(english:"PD9 MegaBBS Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a SQL
injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MegaBBS, a web-based bulletin board 
system written in ASP.

The remote version of this software is vulnerable to a SQL 
injection attack due to a lack of sanitization of 
user-supplied input. An attacker may exploit this flaw to 
issue arbitrary statements in the remote database, and 
therefore, bypass authorization or even overwrite arbitrary 
files on the remote system." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/28");
 script_cvs_date("$Date: 2012/12/13 23:15:37 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:pd9_software:megabbs");
script_end_attributes();

 
 summary["english"] = "Checks for the presence of MegaBBS";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port))
  exit(1, "The remote web Server on port "+port+" does not support PHP.");

function check(loc)
{
 local_var r;
  
 r = http_send_recv3(port:port, method:"GET", item:string(loc, "/index.asp"));  

 if( isnull(r) )exit(1,"Null response to index.asp request.");

 if( "MegaBBS ASP Forum Software" >< r[2] &&
     egrep(pattern:"MegaBBS ASP Forum Software</a>v([0-1]\..*|2\.[0-1]\..*)", string:r[2]) )
 {
 	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
 }
}

foreach dir ( cgi_dirs() )
 check(loc:dir);
