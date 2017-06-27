#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25525);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/11/03 20:40:06 $");

  script_cve_id("CVE-2007-2449");
  script_bugtraq_id(24476);
  script_osvdb_id(36080);

  script_name(english:"Apache Tomcat snoop.jsp URI XSS");
  script_summary(english:"Checks for an XSS flaw in Tomcat's snoop.jsp.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat web server contains a JSP application that is
affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Apache Tomcat web server includes an example JSP
application, 'snoop.jsp', that fails to sanitize user-supplied input
before using it to generate dynamic content. An unauthenticated,
remote attacker can exploit this issue to inject arbitrary HTML or
script code into a user's browser to be executed within the security
context of the affected site.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Jun/182");
  script_set_attribute(attribute:"solution", value:"Undeploy the Tomcat examples web application.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 8080);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# Unless we're paranoid, make sure the banner looks like Tomcat.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner || "Server: Apache-Coyote" >!< banner) exit(0);
}

# Send a request to exploit the flaw.
xss = raw_string("<script>alert('", SCRIPT_NAME, "')</script>");
exploit = string(";", xss, "test.jsp");
foreach dir (make_list("/examples/jsp", "/jsp-examples"))
{
  if ("/examples/jsp" == dir)
  {
    w = http_send_recv3(
      method:"GET", 
      item:string(dir, "/snp/snoop.jsp"), 
      port:port, 
      add_headers: make_array("Host", xss),
      exit_on_fail:TRUE
    );
  }
  else
  {
    w = http_send_recv3(
      method: "GET", 
      item:string(dir, "/snp/snoop.jsp", exploit), 
      port:port, 
      exit_on_fail:TRUE
    );
  }
  res = w[2];

  # There's a problem if our exploit appears in the request URI.
  if (
    ("/examples/jsp" == dir && string("Server name: ", xss) >< res) ||
    (string("Request URI: /jsp-examples/snp/snoop.jsp", exploit) >< res)
  ) 
  {
    if (report_verbosity > 0)
    {
      report = 
       '\n' + 'Nessus was able to exploit the issue using the following HTTP request :' +
       '\n' +
       '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + 
       '\n' + chomp(http_last_sent_request()) +
       '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
