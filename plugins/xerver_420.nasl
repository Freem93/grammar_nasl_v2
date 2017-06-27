#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20062);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/01/22 20:35:42 $");

  script_cve_id("CVE-2005-3293", "CVE-2005-4774");
  script_bugtraq_id(15135);
  script_osvdb_id(20075, 20076, 20077);

  script_name(english:"Xerver < 4.20 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in Xerver < 4.20.");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Xerver prior to 4.20. It is,
therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists that is
    triggered when a '.' is appended to the filename of a
    script in a URL. A remote attacker can exploit this to
    disclose the source code of the script. (CVE-2005-3293
    / OSVDB 20075)

  - An information disclosure vulnerability exists that is
    triggered when a specially crafted HTTP request ending
    with a null character (%00) at the end is sent. A remote
    attacker can exploit this to disclose directly listings.
    (CVE-2005-3293 / OSVDB 20076)

  - A cross-site scripting vulnerability exits due to an
    unspecified flaw. A remote attacker can exploit this,
    via a specially crafted URL containing a null character
    (%00) followed by malicious code, to execute arbitrary
    script code in a user's browser. (CVE-2005-4774)");
 script_set_attribute(attribute:"see_also", value:"http://securitytracker.com/alerts/2005/Oct/1015079.html");
 script_set_attribute(attribute:"solution", value:
"Upgrade to Xerver 4.20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/20");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value: "cpe:/a:xerver:xerver");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80);

# Unless we're paranoid, make sure the banner looks like Xerver.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if ("Server: Xerver" >!< banner)
    audit(AUDIT_WRONG_WEB_SERVER, port, "Xerver");
}

# Get the initial page.
#
# nb: Xerver doesn't deal nicely with http_keepalive_send_recv() for
#     some reason so we don't use it below.
res = http_get_cache(item:"/", port:port, exit_on_fail: 1);

# If that's a directory listing...
if ("<TITLE>Directory Listing" >< res) {
  if (!get_kb_item("www/" + port + "/generic_xss")) {
    # Try to exploit the XSS flaw.
    xss = "<script>alert('" + SCRIPT_NAME + "')</script>";
    r = http_send_recv3(method:"GET", item:raw_string("/%00/", urlencode(str:xss), "/"), port:port, exit_on_fail: TRUE);
    res = r[2];
    # There's a problem if we see our XSS.
    if (
      "<TITLE>Directory Listing" >< res &&
      xss >< res
    ) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    }
  }
}
# Otherwise...
else {
  # Try to force a directory listing.
  r = http_send_recv3(method: "GET", item:"/%00/", port:port, exit_on_fail: TRUE);
  res = r[2];
  # There's a problem if we now get a directory listing.
  if ("<TITLE>Directory Listing" >< res) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
