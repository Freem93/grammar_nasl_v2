#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(12008);
  script_version("$Revision: 1.18 $");
  script_cve_id("CVE-2004-0068");
  script_bugtraq_id(9424);
  script_osvdb_id(3505);

  script_name(english:"PhpDig config.php relative_script_path Parameter Remote File Inclusion");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be executed on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running phpdig, an http search engine written in PHP.
There is a flaw in this product that could allow an attacker to execute
arbitrary PHP code on this by forcing this set of CGI to include a PHP
script hosted on a third-party host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/01/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/01/15");
 script_cvs_date("$Date: 2014/04/23 16:40:39 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpdig.net:phpdig");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpdig.net:phpdig");
script_end_attributes();


  script_summary(english:"Detect phpdig code injection vuln");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("webmirror.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if (! can_host_php(port:port) ) exit(0);


function check_dir(path)
{
 local_var u, r, res;
 u = strcat(path, "/includes/config.php?relative_script_path=http://xxxxxxx");
 r = http_send_recv3(method: "GET", item: u, port:port);
 if (isnull(r)) exit(0);
 res = strcat(r[0], r[1], '\r\n', r[2]);
 if ("http://xxxxxxx/libs/.php" >< res) 
 {
  security_hole(port);
  exit(0);
 }
}

foreach dir (cgi_dirs())
{
check_dir(path:dir);
}
