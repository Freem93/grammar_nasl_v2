#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(17256);
  script_version("$Revision: 1.21 $");

  script_cve_id("CVE-2005-0645", "CVE-2005-2393");
  script_bugtraq_id(12691, 14328);
  script_osvdb_id(14309, 18081, 18082);
 
  script_name(english:"CuteNews <= 1.3.6 Multiple XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains several PHP scripts that are prone to
multiple flaws, including possible arbitrary PHP code execution." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the remote host is running a version
of CuteNews that allows an attacker to inject arbitrary script through
the variables 'X-FORWARDED-FOR' or 'CLIENT-IP' when adding a comment. 
On one hand, an attacker can inject a client-side script to be
executed by an administrator's browser when he/she chooses to edit the
added comment.  On the other, an attacker with local access could
leverage this flaw to run arbitrary PHP code in the context of the web
server user. 

Additionally, it suffers from a cross-site scripting flaw involving
the 'search.php' script." );
 script_set_attribute(attribute:"see_also", value:"http://www.kernelpanik.org/docs/kernelpanik/cutenews.txt" );
 # https://web.archive.org/web/20060512183730/http://retrogod.altervista.org/cutenews.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c580ee7f" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/01");
 script_cvs_date("$Date: 2017/05/11 13:46:37 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_summary(english:"Checks for multiple vulnerabilities in CuteNews <= 1.3.6");

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("cutenews_detect.nasl");
  script_require_keys("www/cutenews");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/cutenews"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # 1.3.6 is known to be affected; previous versions likely are too.
  if (ver =~ "^(0.*|1\.([0-2].*|3[^.]?|3\.[0-6]))") {
    security_note(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
