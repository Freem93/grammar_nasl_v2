#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22465);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/11/02 14:37:09 $");

  script_cve_id("CVE-2006-5114");
  script_bugtraq_id(20244);
  script_osvdb_id(29489);

  script_name(english:"SAP Internet Transaction Server wgate Multiple Parameter XSS");
  script_summary(english:"Checks for an XSS flaw in SAP Internet Transaction Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is vulnerable to a
cross-site scripting attack.");
  script_set_attribute(attribute:"description", value:
"The remote web server fails to sanitize the contents of the 'urlmime'
parameter to the '/scripts/wgate' script before using it to generate
dynamic web content.  An unauthenticated, remote attacker may be able to
leverage this issue to inject arbitrary HTML and script code into a
user's browser to be evaluated within the security context of the
affected website.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2006/Sep/468");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:sap:internet_transaction_server");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0, "The web server on port "+port+" is vulnerable to cross-site scripting");

# Generate a request to exploit the flaw.
xss = string('"><script>alert("', SCRIPT_NAME, '")</script><img src="');
w = http_send_recv3(method:"GET",
  item:string("/scripts/wgate/!?~urlmime=", urlencode(str:xss)), 
  port:port
);

if (isnull(w)) exit(1, "The web server on port "+port+ " did not answer");
res = w[2];

# There's a problem if...
if (
  # it's SAP ITS and...
  "SAP Internet Transaction Server" >< res &&
  # we see our exploit
  (
    string('<td background="', xss) >< res ||
    string('><img src="', xss) >< res ||
    # nb: this vector requires a minor tweak in the published exploit
    #     to actually pop up an alert.
    string('language="JavaScript1.2" src=', "'", xss) >< res
  )
)
{
 security_warning(port);
 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
