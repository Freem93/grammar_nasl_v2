#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20213);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2005-3680");
  script_bugtraq_id(15406);
  script_osvdb_id(20853, 20854, 20855);

  script_name(english:"XOOPS xoopsConfig[language] Parameter Local File Inclusion (XOOPS_WFd205_xpl)");
  script_summary(english:"Checks for xoopsConfig parameter local file inclusion vulnerabilities in XOOPS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple local file inclusion issues." );
 script_set_attribute(attribute:"description", value:
"The remote installation of XOOPS fails to sanitize user-supplied input
to the 'xoopsConfig[language]' parameter of several xoopseditor
scripts before using it in PHP 'include' functions.  An
unauthenticated attacker may be able to leverage these issues to read
arbitrary local files and even execute arbitrary PHP code, subject to
the privileges of the web server user id.  Successful exploitation
requires that PHP's 'register_globals' setting be enabled and possibly
that 'magic_quotes_gpc' be disabled." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/xoops_xpl.html" );
 script_set_attribute(attribute:"solution", value:
"Disable PHP's 'register_globals' setting and enable its
'magic_quotes_gpc' setting." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/11/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/11/12");
 script_cvs_date("$Date: 2012/10/30 01:28:27 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:xoops:xoops");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");

  script_dependencies("xoops_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/xoops");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/xoops"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw to read a file.
  #
  # nb: header.php in XOOP's main directory is useful because it should
  #     always be present, returns a message if called directly, and its
  #     use doesn't depend on magic_quotes_gpc.
  file = "../../../../header";
  if (thorough_tests) editors = make_list("dhtmltextarea", "koivi", "textarea");
  else editors = make_list("textarea");

  foreach editor (editors) {
    r = http_send_recv3(method:"GET", port:port,
      item:string(
        dir, "/class/xoopseditor/", editor, "/editor_registry.php?",
        "xoopsConfig[language]=", file
      ));
    if (isnull(r)) exit(0);

    # There's a problem if we get a message about "root path".
    if ("XOOPS root path not defined" >< r[2]) {
      security_warning(port);
      exit(0);
    }
  }
}
