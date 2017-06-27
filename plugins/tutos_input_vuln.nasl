#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14793);
 script_version("$Revision: 1.17 $");

 script_bugtraq_id(10129);
 script_osvdb_id(5326, 5327, 5328, 5329);

 script_name(english:"TUTOS < 1.1.20040412 Multiple Input Validation Issues");

 script_set_attribute(
   attribute:"synopsis",
   value:"A web application on the remote host has multiple vulnerabilities."
 );
 script_set_attribute(
   attribute:"description",
   value:
"The remote host is running Tutos, an open source team organization
software package written in PHP.

According to its banner, the remote version of this software is
vulnerable to multiple input validation flaws that could allow an
authenticated user to perform a cross-site scripting attack, path
disclosure attack or a SQL injection against the remote service."
 );
 script_set_attribute(
   attribute:"solution",
   value:"Upgrade to Tutos-1.1.20040412 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/04/13");

 script_cvs_date("$Date: 2015/02/13 21:07:14 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value: "cpe:/a:tutos:tutos");
 script_end_attributes();
 
 script_summary(english:"Checks the version of Tutos");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);


foreach dir (cgi_dirs()) 
 {
  req = http_get(item:dir + "/php/mytutos.php", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) exit(0);
  if ( '"GENERATOR" content="TUTOS' >< res &&
       egrep(pattern:".*GENERATOR.*TUTOS (0\..*|1\.(0\.|1\.(2003|20040[1-3]|2004040[0-9]|2004041[01])))", string:res) )
	{
	 security_hole(port);
	 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	 set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	 exit(0);
	}
 }

