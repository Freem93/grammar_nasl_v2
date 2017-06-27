#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(17634);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2005-0896");
  script_bugtraq_id(12900);
  script_osvdb_id(15067);

  script_name(english:"phpMyDirectory review.php subcat Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to
multiple cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The version of phpMyDirectory installed on the remote host suffers
from multiple cross-site scripting vulnerabilities due to its failure
to sanitize user input to its 'review.php' script through various
parameters.  A remote attacker can exploit these flaws to steal
cookie-based authentication credentials and perform other such
attacks." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Mar/444" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyDirectory version 10.1.6 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/25");
 script_cvs_date("$Date: 2016/11/02 14:37:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpmydirectory:phpmydirectory");
script_end_attributes();


  script_summary(english:"Checks for multiple cross-site scripting vulnerabilities in PHPMyDirectory's review.php");

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# A simple alert.
xss = string("<script>alert('", SCRIPT_NAME, "');</script>");
exss = urlencode(str:xss);


# Check various directories for PHPMyDirectory.
test_cgi_xss(port: port, dirs: cgi_dirs(), cgi: "/review.php",
 ctrl_re: '<META name="copyright" CONTENT="Copyright, phpMyDirectory\\.com.',
 pass_str: xss,
 qs: string(
      "id=1&",
      "cat=&",
      'subcat=%22%3E' , exss
    ) );
