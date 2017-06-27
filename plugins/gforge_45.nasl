#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19314);
  script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2015/01/23 22:03:55 $");

  script_cve_id("CVE-2005-2430");
  script_bugtraq_id(14405);
  script_osvdb_id(
    18299,
    18300,
    18301,
    18302,
    18303,
    18304
  );

  script_name(english:"GForge <= 4.5 Multiple Script XSS");
  script_summary(english:"Checks for multiple cross-site scripting vulnerabilities in Gforge <= 4.5");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by
multiple cross-site scripting vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running GForge, an open source software development
collaborative toolset using PHP and PostgreSQL.

The installed version of GForge on the remote host fails to properly
sanitize user-supplied input to several parameters / scripts before
using it in dynamically-generated pages.  An attacker can exploit
these flaws to launch cross-site scripting attacks against the
affected application." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/406723/30/0/threaded");
 script_set_attribute(attribute:"solution", value:"Unknown at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/28");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/29");

script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:gforge:gforge");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
  script_dependencies("gforge_detect.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/gforge");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP");
if (get_kb_item("www/"+port+"/generic_xss")) exit(0, "The web server on port "+port+" is prone to XSS");


# A simple alert.
xss = '<script>alert("' + SCRIPT_NAME + '");</script>';

install = get_install_from_kb(appname:'gforge', port:port);
if (isnull(install)) exit(0, "The 'www/"+port+"/gforge' KB item is missing.");

dir = install['dir'];

# Try to exploit one of the flaws.
w = http_send_recv3(method:"GET",
     item:string(
      dir, "/forum/forum.php?",
      "forum_id=", urlencode(str:string('">', xss))
    ),
    port:port
  );
  if (isnull(w)) exit(1, "the web server on port "+port+" failed to respond");
  res = w[2];

  # There's a problem if we see our XSS as part of a PostgreSQL error.
  if (string('pg_atoi: error in "">', xss) >< res) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
