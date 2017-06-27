#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(15403);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2004-1566", "CVE-2004-1567");
  script_bugtraq_id(11284);
  script_xref(name:"OSVDB", value:"10452");
  script_xref(name:"OSVDB", value:"10453");

  script_name(english:"Silent-Storm Portal Multiple Input Validation Vulnerabilities");
  script_summary(english:"Checks for vulnerabilities in Silent-Storm Portal");
 
  script_set_attribute(  attribute:"synopsis",  value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities."  );
  script_set_attribute(  attribute:"description",   value:
"The remote host is running Silent-Storm, a web-based forum management
software written in PHP.

There are multiple input validation flaws in the remote version of
this software :

  - There is a cross-site scripting vulnerability involving
    the 'module' parameter of the 'index.php' script.

  - The application fails to sanitize the 'mail' parameter
    to the 'profile.php' script, which could be abused to
    inject arbitrary data into the 'users.dat' database
    file and, for example, gain administrative access to
    the application."  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/bugtraq/2004/Sep/456"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Unknown at this time."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/30");
 script_cvs_date("$Date: 2016/11/17 15:28:26 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

  script_family(english:"CGI abuses");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);

test_cgi_xss(port: port, cgi: "/index.php", qs: "module=<script>foo</script>",
    pass_str: "<script>foo</script>", ctrl_re: "copyright silent-storm\.co.uk",
    high_risk: TRUE);
