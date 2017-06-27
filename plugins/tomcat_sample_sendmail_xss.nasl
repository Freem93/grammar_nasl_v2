#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25995);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/03 20:40:06 $");

  script_cve_id("CVE-2007-3383");
  script_bugtraq_id(24999);
  script_osvdb_id(39000);

  script_name(english:"Apache Tomcat SendMailServlet sendmail.jsp 'mailfrom' Parameter XSS");
  script_summary(english:"Checks for an XSS flaw in a sample app from Tomcat.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a JSP application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server includes an example JSP application that fails
to sanitize user-supplied input before using it to generate dynamic
content in the 'examples/SendMailServlet' servlet. An unauthenticated
remote attacker can exploit this issue to inject arbitrary HTML or
script code into a user's browser to be executed within the security
context of the affected site.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Jul/448");
  script_set_attribute(attribute:"solution", value:
"Undeploy the Tomcat examples web application.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default: 8080);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# Unless we're paranoid, make sure the banner looks like Tomcat.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner || "Server: Apache-Coyote" >!< banner) exit(0);
}

# Make sure the affected script exists.
url = "/examples/SendMailServlet";
w = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(w)) exit(1, "the web server did not answer");
res = w[2];


# If it does...
if ("HTTP Status 405 - HTTP method GET is not supported" >< res)
{
  # Send a request to exploit the flaw.
  xss = raw_string("<script>alert(", SCRIPT_NAME, ")</script>");
  postdata = string(
    "mailfrom=", urlencode(str:xss), "&",
    "mailto=&",
    "mailsubject=&",
    "mailcontent="
  );
  w = http_send_recv3(method: "POST", item: url, port: port,
    content_type: "application/x-www-form-urlencoded",
    data: postdata);
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # There's a problem if our exploit appears in the exception message.
  if (string("Extra route-addr in string ``", xss, "'' at") >< res)
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
