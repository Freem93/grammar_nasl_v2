#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20383);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2006-0125");
  script_bugtraq_id(16166);
  script_osvdb_id(22228);

  script_name(english:"AppServ appserv/main.php appserv_root Parameter Remote File Inclusion");
  script_summary(english:"Checks for appserv_root parameter remote file include vulnerability in AppServ");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a remote file inclusion
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running AppServ, a compilation of
Apache, PHP, MySQL, and phpMyAdmin for Windows and Linux. 

The version of AppServ installed on the remote host fails to sanitize
user-supplied input to the 'appserv_root' parameter of the
'appserv/main.php' script before using it in a PHP 'include' function. 
An unauthenticated attacker can exploit this flaw to run arbitrary
code, possibly taken from third-party hosts, subject to the privileges
of the web server user id.  Note that AppServ under Windows runs with
SYSTEM privileges, which means an attacker can gain complete control
of the affected host." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/01/05");
 script_cvs_date("$Date: 2012/11/28 23:06:40 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:appserv_open_project:appserv");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006-2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Try to exploit the flaw.
#
# nb: AppServ is always installed under "/appserv".
r = http_send_recv3(method:"GET", port:port,
  item:string("/appserv/main.php?appserv_root=", SCRIPT_NAME) );
if (isnull(r)) exit(0);
res = r[2];

# There's a problem if we get an error saying "failed to open stream".
if (egrep(pattern:string(SCRIPT_NAME, "/lang-.+\\.php\\): failed to open stream"), string:res)) {
  security_warning(port);
  exit(0);
}
