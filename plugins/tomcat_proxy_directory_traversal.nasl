#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43623);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/10/19 14:37:27 $");

  script_cve_id("CVE-2007-0450");
  script_bugtraq_id(22960);
  script_osvdb_id(34769);
  script_xref(name:"Secunia", value:"24732");

  script_name(english:"Apache Tomcat Directory Traversal");
  script_summary(english:"Attempts to access /manager/html.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a directory traversal
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server proxies certain requests to an Apache Tomcat
server and allows directory traversal attacks due to Tomcat allowing
'/', '\', and '%5c' characters as directory separators. 

By sending a specially crafted request, it is possible for an attacker
to break out of the given context and access web applications that may
not otherwise be proxied to the Tomcat web server.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-5.html");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-6.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/462791/100/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache Tomcat 5.5.22 / 6.0.10 / 4.1.36 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
# nb: no sense testing Tomcat itself -- the issue involves proxied requests.
if (
  banner && 
  (
    "Apache-Coyote" >< banner ||
    "Tomcat" >< banner
  )
) exit(0, "The web server on port "+port+" is Tomcat.");

if (thorough_tests) dirs = list_uniq(make_list("/examples", "/samples", cgi_dirs()));
else dirs = make_list(cgi_dirs());

rand = SCRIPT_NAME + unixtime();

foundtomcat = FALSE;
foreach dir (dirs)
{
  if (report_paranoia < 2)
  {
    res = http_send_recv3(method:"GET", item:dir+"/"+rand, fetch404:TRUE, port:port);
    if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");
    if ('Apache Tomcat/' >< res[2]) foundtomcat = TRUE;
  }
  if (
    (report_paranoia == 2) ||
    (report_paranoia < 2 && foundtomcat)
  )
  {
    res = http_send_recv3(method:"GET", item:dir+"/\../manager/html", port:port);
    if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");
    if (
      '<h1>401 Unauthorized</h1>' >< res[2] &&
      'You are not authorized to view this page.' >< res[2]
    )
    {
      if (report_verbosity > 0)
      {
        report = 
          '\n'+
          'Nessus was able to access the Tomcat manager application with the\n'+
          'following URL :\n'+
          '\n'+
          build_url(qs:dir+"/\../manager/html", port:port)+
          '\n';
        security_warning(port:port, extra:report);
      }
      else security_warning(port:port);
      exit(0);
    }
  }
}
if (report_paranoia < 2 && !foundtomcat) exit(0, 'The web server on port '+port+' is not affected because requests are not proxied to Apache Tomcat');
else if (report_paranoia < 2) exit(0, 'Apache Tomcat is configured to receive requests from web server on port '+port+' but is not affected.');
