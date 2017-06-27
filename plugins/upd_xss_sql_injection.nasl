#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18260);
 script_version("$Revision: 1.17 $");

 script_cve_id("CVE-2005-1614", "CVE-2005-1615", "CVE-2005-1616");
 script_bugtraq_id(13621, 13622);
 script_osvdb_id(16771, 16772, 16773);
 
 script_name(english:"Ultimate PHP Board < 1.9.7 viewforum.php Multiple Vulnerabilities");

  script_set_attribute(
    attribute:"synopsis",
    value:"A web application on the remote host has multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running Ultimate PHP Board (UPB).  The remote
version of this software is vulnerable to cross-site scripting
attacks, and SQL injection flaws.

Using a specially crafted URL, an attacker may execute arbitrary
commands against the remote SQL database or use the remote server to
set up a cross-site scripting attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2005/May/164"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to UPB 1.9.7 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/13");
 script_cvs_date("$Date: 2016/11/15 19:41:08 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
 script_summary(english:"Checks for UPB");
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

# The script code starts here

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


foreach d ( cgi_dirs() )
{
 req = http_get(item:string(d, "/index.php"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if(egrep(pattern:"Powered by UPB Version :.* (0\.|1\.([0-8][^0-9]|9[^0-9]|9\.[1-6][^0-9]))", string:res))
 {
 	security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
 }
}
