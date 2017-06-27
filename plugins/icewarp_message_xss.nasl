#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29895);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2011/08/25 20:49:06 $");

  script_cve_id("CVE-2008-0218");
  script_bugtraq_id(27189);
  script_osvdb_id(40221);

  script_name(english:"IceWarp Mail Server admin/index.html message Parameter XSS");
  script_summary(english:"Checks for an XSS flaw in IceWarp Web Mail");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a script that is affected by a cross-
site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running IceWarp Merak Mail Server, a webmail server
for Windows and Linux. 

The remote version of IceWarp fails to sanitize user input to the
'message ' parameter of the 'admin/index.html' script before using it
to generate dynamic content.  An unauthenticated, remote attacker may
be able to leverage this issue to inject arbitrary HTML or script code
into a user's browser to be executed within the security context of
the affected site.");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_publication_date", value: "2008/01/09");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:icewarp:webmail");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 4096, 32000);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:32000);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# Unless we're being paranoid, make sure the banner belongs to IceWarp.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner || "IceWarp" >!< banner) exit(0);
}


# Try to exploit the issue.
xss = string("<script>alert('", SCRIPT_NAME, "')</script>");

w = http_send_recv3(method:"GET",
  item:string(
    "/admin/index.html?",
    "message=", urlencode(str:xss)
  ), 
  port:port
);
if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
res = w[2];

# There's a problem if...
if (
  # it's IceWarp and ...
  (
    '>IceWarp Merak Mail Server<' >< res ||
    'alt="Icewarp WebAdmin"' >< res
  ) &&
  # the output has our "message"
  string('class="message">', xss, '</td>') >< res
)
{
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
}
