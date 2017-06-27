#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18201);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2005-1443");
  script_bugtraq_id(13483);
  script_xref(name:"OSVDB", value:"16488");

  script_name(english:"Invision Power Board index.php Multiple Parameter XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to cross-
site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The version of Invision Power Board installed on the remote host
suffers from a cross-site scripting vulnerability due to its failure
to sanitize user input via the 'act' parameter to the 'index.php'
script.  An unauthenticated attacker can exploit this flaw by
injecting malicious HTML and script code through the nickname field to
redirect forum visitors to arbitrary sites, steal authentication
cookies, and the like. 

Additional parameters in the index.php script have been reported 
vulnerable. However, Nessus has not checked for them." );
 script_set_attribute(attribute:"see_also", value:"http://www.governmentsecurity.org/forum/index.php?act=ST&f=26&t=14656" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Invision Power Board 2.0.4 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/29");
 script_cvs_date("$Date: 2015/01/14 03:46:11 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:invisionpower:invision_power_board");
script_end_attributes();

 
  summary["english"] = "Checks for act parameter cross-site scripting vulnerability in Invision Power Board";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("invision_power_board_detect.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/invision_power_board");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "');</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  test_cgi_xss(port: port, cgi: "/index.php", dirs: make_list(dir),
 qs: strcat("act=", exss), pass_str: xss);
}
