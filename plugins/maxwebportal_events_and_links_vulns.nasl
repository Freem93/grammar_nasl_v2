#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(17688);
  script_version("$Revision: 1.20 $");

  script_cve_id("CVE-2005-1016", "CVE-2005-1017", "CVE-2005-1417");
  script_bugtraq_id(12968, 13466);
  script_osvdb_id(
    15196,
    15197,
    16306,
    16307,
    16308,
    16309,
    16310,
    16311,
    16312,
    16313,
    16314,
    16315,
    16316,
    16317,
    16318
  );

  name["english"] = "MaxWebPortal <= 1.33 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of MaxWebPortal that is prone to
multiple input validation vulnerabilities:

  - Multiple SQL Injection Vulnerabilities
    An attacker can inject SQL statements via various scripts 
    to manipulate database queries.

  - A Cross-Site Scripting Vulnerability
    An attacker can pass arbitrary HTML and script code via
    the 'banner' parameter of the 'links_add_form.asp' script
    to be executed by a user's browser in the context of the
    affected website whenever he views the malicious link." );
 script_set_attribute(attribute:"see_also", value:"http://www.hackerscenter.com/archive/view.asp?id=1807" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/01");
 script_cvs_date("$Date: 2014/04/25 21:05:50 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Checks for multiple vulnerabilities in MaxWebPortal <= 1.33");
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");

  script_dependencie("cross_site_scripting.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ASP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_asp(port:port)) exit(0, "The web server on port "+port+" does not support ASP");


# Some variables to use when trying an exploit.
# - a url to submit.
#   nb: gettimeofday() ensures the URL is unique (otherwise,
#       MaxWebPortal will reject the submission).
new_url = string("http://www.example.com/", gettimeofday());
# - the submitter's email address.
from = get_kb_item("SMTP/headers/From");
if (!from) from = "nobody@example.com";
# - a simple alert to display "Nessus was here".
xss = "<script>alert('Nessus was here');</script>";
#   nb: the url-encoded version is what we need to pass in.
exss = "%3Cscript%3Ealert('Nessus%20was%20here')%3B%3C%2Fscript%3E";


# Check various directories for MaxWebPortal.
foreach dir (cgi_dirs()) {
  # Pull up the link add page.
  w = http_send_recv3(method:"GET", item:string(dir, "/links_add_form.asp"), port:port, exit_on_fail: 1);
  res = w[2];

  # If safe checks are enabled...
  if (safe_checks()) {
    # Test the version number.
    #
    # nb: a more complete version number can be found in "site_info.asp".
    if (egrep(string:res, pattern:'<title="Powered By: MaxWebPortal.info Version 1\\.([0-2]|3[0-3])', icase:TRUE)) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
  # Else try the exploit as long as the server itself isn't 
  # vulnerable to XSS attacks.
  #
  # nb: this will not catch those forums that don't accept submissions
  #     or accept them only from logged-in users.
  else if (!get_kb_item("www/"+port+"/generic_xss")) {
    # We need an existing category.
    pat = 'option value="([0-9]+)">';
    matches = egrep(pattern:pat, string:res, icase:TRUE);
    foreach match (split(matches)) {
      match = chomp(match);
      cat = eregmatch(pattern:pat, string:match, icase:TRUE);
      if (!isnull(cat)) {
        cat = cat[1];
        break;
      }
    }
    # If we don't have one, take a wild guess.
    if (isnull(cat)) cat = 2;

    postdata = string(
      "cat=", cat, "&",
      "name=Nessus+Plugin+Test&",
      "url=", new_url, "&",
      "mail=", from, "&",
      "des=Generated+automatically+by+", SCRIPT_NAME, "&",
      "key=&",
      "banner=%3E", exss, "&",
      "B1=Submit"
    );
    w = http_send_recv3(method:"POST",  port: port,
      item: dir+"/links_add_url.asp", 
      content_type: "application/x-www-form-urlencoded",
      exit_on_fail: 1, data: postdata);

    # If we see our exploit, there's a problem.
    if (xss >< res) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
