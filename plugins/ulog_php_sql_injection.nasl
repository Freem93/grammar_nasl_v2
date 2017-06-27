#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(14363);
 script_bugtraq_id(11018);
 script_osvdb_id(51268);
 script_version("$Revision: 1.15 $");
 
 script_name(english:"INL ulog-php port.php proto Parameter SQL Injection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is vulnerable to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ulog-php, a firewall log analysis interface
written in PHP. 

There is a SQL injection vulnerability in the remote interface, in the
'port.php' script that may allow an attacker to insert arbitrary SQL
statements into the remote database.  An attacker may exploit this
flaw to add bogus statements to the remote log database or to remove
arbitrary log entries from the database, thus clearing his tracks." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ulog-php 0.8.2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/24");
 script_cvs_date("$Date: 2011/03/12 01:05:17 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Checks for the presence of a SQL injection vulnerability in ulog";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 local_var  r;

 r = http_send_recv3(method:"GET", item:string(loc, "/port.php?proto=tcp'"), port:port);
 if( r == NULL )exit(0);
 if('select ip_saddr,ip_daddr,ip_protocol,oob_time_sec,tcp_sport,tcp_dport,udp_sport,udp_dport,oob_prefix,id' >< r[2] )
 {
 	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
 }
}


foreach dir (cgi_dirs())
{
 check(loc:dir);
}

