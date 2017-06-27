#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43101);

  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2009-4237");
  script_bugtraq_id(37258);
  script_xref(name:"OSVDB", value:"60914");

  script_name(english:"TestLink login.php req Parameter XSS");
  script_summary(english:"Checks for an XSS issue in TestLink");

  script_set_attribute(attribute:"synopsis",value:
"The remote web server is hosting a PHP application that is affected
by a cross-site scripting vulnerability."
  );
  script_set_attribute(attribute:"description",value:
"The remote web server is hosting TestLink, a test-management
application written in PHP. 

The installed version of TestLink is affected by a cross-site
scripting vulnerability in the 'req' parameter of the 'login.php'
script.  An attacker could exploit this flaw to execute arbitrary
script code in a user's browser. 

Note that this version is potentially affected by multiple other
issues, though Nessus has not tested for these."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b28f9d8c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?851b4c6f"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to TestLink version 1.8.5 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(79);
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/12/09"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/12/09"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/12/10"
  );
 script_cvs_date("$Date: 2011/03/07 16:28:07 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");
  script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");

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
if (!can_host_php(port:port)) exit(0, "The remote web server on port "+port+" does not support PHP.");

if (thorough_tests) 
  dirs = list_uniq(make_list("/testlink", cgi_dirs()));
else 
  dirs = make_list(cgi_dirs());

exploit = '"><script>alert('+"'"+SCRIPT_NAME+'-'+unixtime()+"'"+')</script>';
expected_output='<input type="hidden" name="reqURI" value="'+exploit+'"/>';

exploited = test_cgi_xss(
  port:port,
  dirs:dirs,
  cgi:"/login.php",
  qs:'req='+exploit,
  pass_str:expected_output,
  ctrl_re:'TestLink is licensed under the'
);
if (exploited) exit(0);
