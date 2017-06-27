#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(16071);
 script_version ("$Revision: 1.19 $");

 script_cve_id("CVE-2004-1423");
 script_bugtraq_id(12127, 20657);
 script_osvdb_id(12700, 12701);

 script_name(english:"PHP-Calendar Multiple Script phpc_root_path Parameter Remote File Inclusion");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote file include vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote web server is running PHP-Calendar, a web-based calendar
written in PHP. 

The remote version of this software is vulnerable to a file inclusion
flaw that could allow an attacker to execute arbitrary PHP commands on
the remote host." );
  # http://web.archive.org/web/20061010145640/http://www.gulftech.org/?node=research&article_id=00060-12292004
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3abcef5" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Dec/436" );
  # http://sourceforge.net/project/shownotes.php?release_id=296020&group_id=46800
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?62470ca6" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP-Calendar version 0.10.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/12/29");
 script_cvs_date("$Date: 2016/11/23 20:42:23 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:php-calendar:php-calendar");
script_end_attributes();

 script_summary(english:"Determines if PHP-Calendar can include third-party files");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

 script_dependencies("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/PHP");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach d (cgi_dirs())
{
 url = string(d, "/includes/calendar.php?phpc_root_path=http://xxxx./");
 r = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(r)) exit(0);
 buf = r[2];
 if ( "http://xxxx./includes/html.php" >< buf )
 {
  security_hole(port);
  exit(0);
 }
}
