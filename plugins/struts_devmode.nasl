#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34947);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/01/30 19:28:01 $");

  script_name(english:"Apache Struts 2 devMode Information Disclosure");
  script_summary(english:"Checks for Struts 2 debug xml output.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a Java framework that is configured to
operate in debug mode."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server is using Apache Struts 2, a web application
framework for developing Java EE web applications.

The version of Apache Struts 2 installed on the remote host is
configured to operate in development mode (devMode). While this
environment can help speed up development of web applications, it can
leak information about the underlying web applications as well as the
installation of Struts, Java, and other related items on the remote
host."
  );
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/devmode.html");
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/debugging.html");
  script_set_attribute(
    attribute:"solution",
    value:
"If this server is used in a production environment, disable
development mode."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("webmirror.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080);

action = "Nessus-" + unixtime();

# Iterate over known directories.
dirs = get_kb_list("www/" +port+ "/content/directories");
if (isnull(dirs)) dirs = make_list("", "/struts2-showcase", "/struts-showcase");

foreach dir (dirs)
{
  # Identify a web app using Struts.
  res = http_send_recv3(
    port   : port,
    method : "GET",
    item   : dir + "/struts/webconsole.html",
    exit_on_fail : TRUE
  );

  # If so...
  if (">OGNL Console<" >< res[2])
  {
    # Try to get XML debugging output for an invalid action.
    url = dir + "/" + action + ".action?debug=xml";

    res = http_send_recv3(
      port   : port,
      method : "GET",
      item   : url,
      exit_on_fail : TRUE
    );

    # There's a problem if we get debug output.
    if (
      "struts.action" >< res[2] &&
      "<debug>" >< res[2]
    )
    {
      security_report_v4(
        port       : port,
        severity   : SECURITY_WARNING,
        generic    : TRUE,
        request    : make_list(build_url(qs:url, port:port)),
        output     : chomp(res[2])
      );
      exit(0);
    }
  }
  if (!thorough_tests) break;
}
exit(0, 'No vulnerable applications were detected on the web server listening on port '+port+'.');
