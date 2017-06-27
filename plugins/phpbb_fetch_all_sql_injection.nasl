#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14226);
 script_version("$Revision: 1.21 $");

 script_bugtraq_id(10868, 10893);
 script_osvdb_id(8353, 8355);

 script_name(english:"phpBB Fetch All < 2.0.12 Multiple Scripts SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to SQL injection." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of phpBB FetchAll older than 2.0.12.

It is reported that this version of phpBB Fetch All is susceptible 
to a SQL injection vulnerability. This issue is due to a failure of
the application to properly sanitize user-supplied input before using 
it in a SQL query.

The successful exploitation of this vulnerability depends on the 
implementation of the web application that includes phpBB Fetch All 
as a component.  It may or may not be possible to effectively pass 
malicious SQL statements to the underlying function. 

Successful exploitation could result in compromise of the application, 
disclosure or modification of data or may permit an attacker to exploit 
vulnerabilities in the underlying database implementation." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpBB Fetch All 2.0.12 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/07");
 script_cvs_date("$Date: 2012/11/02 21:55:17 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Check for phpBB Fetch All version");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 
 script_family(english:"CGI abuses");
 script_dependencie("phpbb_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/phpBB");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port)) exit(0);

kb = get_kb_item("www/" + port + "/phpBB");
if ( ! kb ) exit(0);
matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
location = matches[2];

req = http_get(item:location + "/index.php", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( ! res ) exit(0);

if ( ereg(pattern:"^([01]\..*|2\.0\.([0-9]|1[01])[^0-9])", string:matches[1]))
{
	security_hole(port);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}


