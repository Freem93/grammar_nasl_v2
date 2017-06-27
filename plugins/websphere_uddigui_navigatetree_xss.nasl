#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27803);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_cve_id("CVE-2007-5798", "CVE-2007-5799");
  script_bugtraq_id(26276);
  script_osvdb_id(41618, 41619);

  script_name(english:"IBM WebSphere Application Server navigateTree.do Multiple Vulnerabilities");
  script_summary(english:"Checks for an XSS flaw in WAS' navigateTree.do");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a script that is affected by various
cross-site scripting and cross-site request forgery vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Application installed on the remote host
fails to sanitize input to the 'keyField', 'nameField', 'valueField',
and 'frameReturn' parameters of the 'uddigui/navigateTree.do' script
before using it to generate dynamic content.  An unauthenticated
remote attacker may be able to leverage this issue to inject arbitrary
HTML or script code into a user's browser to be executed within the
security context of the affected site.");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1PK50245");
  script_set_attribute(attribute:"solution", value:
"Apply WebSphere Application Server 6.1.0 fix pack 13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 352);

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 9080, 9443);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


l = get_kb_list("Services/www");
foreach p (make_list(9080, 9443))
  if (get_port_state(p))
    l = add_port_in_list(list: l, port: p);

xss = string("nessus.value=value;}</script>\r\n<script>alert('", SCRIPT_NAME, "')</script>");

function check(port)
{
  local_var	banner, w;

  if (!get_port_state(port)) return 0;
  if (get_kb_item("www/"+port+"/generic_xss")) return 0;


# Unless we're paranoid, make sure the banner looks like WAS.
  if (report_paranoia < 2)
  {
    banner = get_http_banner(port:port);
    if (!banner || "Server: WebSphere Application Server/" >!< banner) return 0;
  }


# Send a request to exploit the flaw.

  w = http_send_recv3(method:"GET", port: port, 
    item:string("/uddigui/navigateTree.do?keyField=", urlencode(str:xss)));
  if (isnull(w)) return 0;

# There's a problem if our exploit appears in the xferName function.
  if ("function xferName" >< w[2] &&
   string("parent.detail.document.forms[0].", xss, ".value = key;") >< w[2])
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    return 1;
  }
  return 0;
}

foreach port (l) check(port: port);
