#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15941);
 script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2015/01/14 20:12:26 $"); 

 script_osvdb_id(7973);

 script_name(english:"PunBB URL Quote Tag XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote version of PunBB is vulnerable to
cross-site scripting attacks because the application does not validate
URL and quote tags.  With a specially crafted URL, an attacker may be
able to inject arbitrary HTML and script code into a user's browser,
resulting in a loss of integrity." );
 script_set_attribute(attribute:"see_also", value:"http://www.punbb.org/changelogs/1.1.4_to_1.1.5.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PunBB version 1.1.5 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/07/14");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks for PunBB version");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 
 script_family(english:"CGI abuses : XSS");
 script_dependencie("punBB_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/punBB");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/punBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (egrep(pattern: "^(0\.|1\.0|1\.1[^.]|1\.1\.[0-4]([^0-9]|$))",string:ver))
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
