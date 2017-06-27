#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(23842);
  script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2014/12/15 22:32:43 $");

  script_name(english:"JBoss JMX Console Unrestricted Access");
  script_summary(english:"Tries to access the JMX and Web Consoles");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server allows unauthenticated access to an
administrative Java servlet.");
 script_set_attribute(attribute:"description", value:
"The remote web server appears to be a version of JBoss that allows
unauthenticated access to the JMX and/or Web Console servlets used to
manage JBoss and its services. A remote attacker can leverage this
issue to disclose sensitive information about the affected application
or even take control of it.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?997637b6");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9b164df" );
 script_set_attribute(attribute:"see_also", value:"http://www.jboss.org/community/wiki/SecureJBoss" );
 script_set_attribute(attribute:"see_also", value:"http://www.jboss.org/community/wiki/SecureTheJmxConsole" );
 script_set_attribute(attribute:"solution", value:
"Secure or remove access to the JMX and/or Web Console using the
advanced installer options.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/14");

script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");

  if ( NASL_LEVEL < 4200 )
    script_dependencies("http_version.nasl", "webmirror.nasl");
  else
    script_dependencies("http_version.nasl", "webmirror.nasl", "alternate_hostnames.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/jboss");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8080, embedded: 0); # Also seen on 80 or 8443 (HTTPS)

banner = get_http_banner(port: port);
if (! egrep(string: banner, pattern: '^X-Powered-By:.*JBoss'))
  exit(0, "The web server on port "+port+" doesn't appear to be JBoss EAP.");

# Check whether access is allowed.
info = "";

# The consoles may be hidden on a special vhost
hnl = get_kb_list("Host/alt_name");
if (isnull(hnl)) hnl = make_list(get_host_name(), get_host_ip());
else hnl = make_list(get_host_name(), get_host_ip(), hnl);
hnl = sort(list_uniq(hnl));

url_l = get_kb_list("www/"+port+"/console");
if (isnull(url_l))
  url_l = make_list("/jmx-console/", "/web-console/");
else
  url_l = list_uniq(make_list("/jmx-console/", "/web-console/", url_l));

foreach h (hnl)
{
  foreach url (url_l)
  {
    if (strlen(info) > 0) ex = 0; else ex = 1;
    r = http_send_recv3(method: "GET", item:url, port:port, host: h, exit_on_fail: ex);
    if (isnull(r))
    {
      debug_print(level:1, "No HTTP answer from port "+port+".");
      break;
    }

  if ("jmx" >< url && '="HtmlAdaptor?action=displayMBeans"' >< r[2])
  {
    set_kb_item(name: "JBoss/"+port+"/jmx-console", value:url);
    set_kb_item(name: "JBoss/reachable/jmx-console", value: TRUE);

    info += string(
      "\n",
      "The JMX Console can be accessed via the following URL :\n",
      "\n",
      "  ", build_url(port:port, qs:url, host: h), "\n"
    );

    if (!thorough_tests) break;
  }
  else if ("web" >< url && ' src="ServerInfo.jsp"' >< r[2])
  {
    set_kb_item(name: "JBoss/"+port+"/web-console", value:url);
    set_kb_item(name: "JBoss/reachable/web-console", value: TRUE);

    info += string(
      "\n",
      "The Web Console can be accessed via the following URL :\n",
      "\n",
      "  ", build_url(port:port, qs:url, host: h), "\n"
    );

    if (!thorough_tests) break;
    }
  }
  if (info) break;
}

if (info)
{
  if (report_verbosity > 0) security_hole(port:port, extra:info);
  else security_hole(port);
}
