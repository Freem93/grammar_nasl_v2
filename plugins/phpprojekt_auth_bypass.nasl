#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15905);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2004-2739");
 script_bugtraq_id(11797);
 script_osvdb_id(12174);

 script_name(english:"PHProjekt setup.php Authentication Bypass Arbitrary Code Execution");

 script_set_attribute(attribute:"synopsis", value:
"The remote web application can be reconfigured without credentials." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHProjekt, an open source PHP Groupware 
package. It runs on most Linux and Unix variants, in addition to 
Microsoft Windows operating systems.

An unspecified authentication bypass vulnerability is present in the 
'setup.php' source file and may be exploited by a remote attacker to 
gain access to the 'setup.php' file without requiring authentication. 
The 'setup.php' file may then be employed to make administrative 
configuration changes to the PHPProjekt website." );
 script_set_attribute(attribute:"solution", value:
"Upgrade setup.php to the fixed version - setup.php,v 1.3." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(264);
 
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/12/02");
 script_cvs_date("$Date: 2012/09/12 01:42:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phprojekt:phprojekt");
script_end_attributes();

 script_summary(english:"Uses a form-POST method to enter the configuration page");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

enable_cookiejar();
init_cookiejar();

r = http_send_recv3(port: port, method: 'GET', item:"/phprojekt/setup.php");

if (! egrep(pattern: "^Set-Cookie:", string: r[1])) exit(0);

r = http_send_recv3(port: port, method: 'POST', 
	item:"/phprojekt/setup.php", 
	data: strcat("nachname=", rand(), "&admin_pw=", rand()),
	add_headers: make_array("Content-Type", "application/x-www-form-urlencoded") );

if (isnull(r)) exit(0);

if("PHProjekt SETUP" >< r[2])
  {
   security_hole(port);
   exit(0);
  }
