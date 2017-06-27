#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18006);
  script_version("$Revision: 1.21 $");

  script_cve_id("CVE-2005-1049");
  script_bugtraq_id(13075, 13076);
  script_xref(name:"OSVDB", value:"15369");
  script_xref(name:"OSVDB", value:"15370");

  script_name(english:"PostNuke < 0.760 RC4 Multiple Script XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to cross-
site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The version of PostNuke installed on the remote host fails to properly
sanitize user input through the 'op' parameter of the 'user.php'
script and the 'module' parameter of the 'admin.php' script before
using it in dynamically-generated content.  An attacker can exploit
this flaw to inject arbitrary HTML and script code into the browser of
unsuspecting users, leading to disclosure of session cookies and the
like." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Apr/118" );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&amp;m=111298226029957&amp;w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 0.760 RC4 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/08");
 script_cvs_date("$Date: 2016/11/02 14:37:08 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:postnuke_software_foundation:postnuke");
 script_end_attributes();

  script_summary(english:"Checks for op and module parameters cross-site scripting vulnerabilities in PostNuke");
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_dependencies("cross_site_scripting.nasl", "postnuke_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/postnuke");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# - A simple alert to display "Nessus was here".
xss = "<script>alert('Nessus was here');</script>";
#   nb: the url-encoded version is what we need to pass in.
exss = "%3Cscript%3Ealert('Nessus%20was%20here')%3B%3C%2Fscript%3E";
n = 0;
cgi[n] = "/admin.php"; qs[n++] = "module=%22%3E" + exss + "&op=main&POSTNUKESID=355776cfb622466924a7096d4471a480";
cgi[n] = "/user.php"; qs[n++] = "op=%22%3E" + exss + "&module=NS-NewUser&POSTNUKESID=355776cfb622466924a7096d4471a480";

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/postnuke"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  # Try to exploit the flaws.
  for (i = 0; i < n; i ++) {
    if (test_cgi_xss(port: port, dirs: make_list(dir), cgi: cgi[i], qs: qs[i], pass_str: xss)) exit(0);
  }
}
