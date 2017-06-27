#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15972);
 script_version("$Revision: 1.20 $");
 script_cve_id("CVE-2004-1402");
 script_bugtraq_id(11946);
 script_osvdb_id(12417, 15449, 15450);

 script_name(english:"iWebNegar Multiple Scripts SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is subject to
multiple SQL injection vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running iWebNegar, a web log application
written in PHP. 

There is a flaw in the remote software that may allow anyone to inject
arbitrary SQL commands and in turn gain administrative access to the
affected application." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Dec/174" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/12/15");
 script_cvs_date("$Date: 2016/10/27 15:03:54 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"SQL Injection");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if ( ! can_host_php(port:port) ) exit(0);


foreach dir (cgi_dirs()) 
 {
  w = http_send_recv3(method:"GET", item:dir + "/index.php?string='", port:port);
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];
  if ("iWebNegar" >< res &&
     egrep(pattern:"mysql_fetch_array\(\).*MySQL", string:res) ) 
	{
	  security_hole(port);
	  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	  exit(0);
	}
 }
