#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18251);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2005-1327");
  script_bugtraq_id(13353);
  script_osvdb_id(15907);

  script_name(english:"Woltlab Burning Board pms.php folderid Parameter XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script which is vulnerable to a
cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The version of Burning Board or Burning Board Lite installed on the
remote host may be prone to cross-site scripting attacks due to its
failure to properly sanitize input passed to the 'folderid' parameter
of the 'pms.php' script.  An attacker may be able to exploit this flaw
to cause arbitrary HTML and script code to be run in a user's browser
within the context of the affected website." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/396858" );
 # http://web.archive.org/web/20050515212523/http://www.woltlab.com/news/399_en.php
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29ed52ec" );
 script_set_attribute(attribute:"solution", value:
"Apply the security update referenced above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/24");
 script_cvs_date("$Date: 2015/01/13 20:37:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Checks for cross-site scripting vulnerability in Burning Board's pms.php script");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses : XSS");
  script_dependencies("http_version.nasl", "burning_board_detect.nasl", "cross_site_scripting.nasl");
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
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + " was here');</script>";
# nb: the url-encoded version is what we need to pass in.
exss = "%3Cscript%3Ealert('" + SCRIPT_NAME + "%20was%20here')%3B%3C%2Fscript%3E";

kb1 =   get_kb_list(string("www/", port, "/burning_board"));
if ( isnull(kb1) ) kb1 = make_list();
else kb1 = make_list(kb1);

kb2 =   get_kb_list(string("www/", port, "/burning_board_lite"));
if ( isnull(kb2) ) kb2 = make_list();
else kb2 = make_list(kb2);

# Test any installs.
installs = make_list(kb1, kb2);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    dir = matches[2];

    # Try to exploit it.
    r = http_send_recv3(method: 'GET', item:string(dir, "/pms.php?folderid=", exss), port:port);
    if (isnull(r)) exit(0);

    # There's a problem if we see our XSS.
    if (xss >< r[2]) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}
