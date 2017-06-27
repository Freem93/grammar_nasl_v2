#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(18246);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2005-1650", "CVE-2005-1651", "CVE-2005-1652", "CVE-2005-1653");
  script_bugtraq_id(13597);
  script_osvdb_id(16336, 16337, 16338, 16339);

  name["english"] = "Woppoware PostMaster <= 4.2.2 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote webmail service is affected by multiple flaws." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of Woppoware Postmaster on the
remote host suffers from multiple vulnerabilities:

  - An Authentication Bypass Vulnerability
    An attacker can bypass authentication by supplying an
    account name to the 'email' parameter of the
    'message.htm' page. After this, the attacker can read
    existing messages, compose new messages, etc as the
    specified user.

  - Information Disclosure Vulnerabilities
    The application responds with different messages based
    on whether or not an entered username is valid. It 
    also fails to sanitize the 'wmm' parameter used in
    'message.htm', which could be exploited to conduct
    directory traversal attacks and retrieve arbitrary
    files from the remote host.

  - A Cross-Site Scripting Vulnerability
    The 'email' parameter of the 'message.htm' page is
    not sanitized of malicious input before use." );
 script_set_attribute(attribute:"see_also", value:"http://packetstormsecurity.nl/0505-exploits/postmaster.txt" );
 script_set_attribute(attribute:"solution", value:
"Reconfigure Woppoware Postmaster, disabling the webmail service." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/12");
 script_cvs_date("$Date: 2016/01/07 15:01:56 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in Woppoware PostMaster <= 4.2.2";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 8000);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:8000);
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# Unless we're paranoid, make sure the banner looks like Woppoware.
if (report_paranoia < 2) {
  banner = get_http_banner(port:port);
  if (!banner || "Server: PostMaster" >!< banner) exit(0);
}


# Try to exploit the XSS flaw.
xss = "<script>alert('" + SCRIPT_NAME + "')</script>";
w = http_send_recv3(method:"GET",
  item:string("/message.htm?email=", urlencode(str:xss)), 
  port:port
);
if (isnull(w)) exit(1, "The web server did not answer");
res = w[2];

# There's a problem if we see our XSS.
if (
  "PostMaster Web Mail" >< res && 
  xss >< res
) {
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
