#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(16280);
 script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2016/11/03 14:16:36 $");

 script_osvdb_id(13150);

 script_name(english:"vBulletin BB Tag XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote version of vBulletin is earlier
than 2.3.6 / 3.0.6.  Such versions are reportedly affected by a
cross-site scripting issue involving its BB code parsing.  As a result
of this vulnerability, it is possible for a remote attacker to create
a malicious link containing script code that will be executed in the
browser of an unsuspecting user when followed.  This may facilitate
the theft of cookie-based authentication credentials as well as other
attacks." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Jan/546" );
 script_set_attribute(attribute:"see_also", value:"http://www.vbulletin.com/forum/showthread.php?postid=800224" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to vBulletin version 2.3.6 / 3.0.6 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/31");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/16");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:vbulletin:vbulletin");
script_end_attributes();


 script_summary(english:"Checks BBTag XSS flaw in vBulletin");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("vbulletin_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/vBulletin");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);
  
# Test an install.
install = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (ver =~ '^([0-1]\\.|2\\.([0-2])?[^0-9]|2\\.3(\\.[0-5])?[^0-9]|3\\.0(\\.[0-5])?[^0-9])' )
  {
    security_note(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
