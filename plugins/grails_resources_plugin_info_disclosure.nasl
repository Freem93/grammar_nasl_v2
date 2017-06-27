#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72757);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/24 21:08:39 $");

  script_cve_id("CVE-2014-0053", "CVE-2014-2857", "CVE-2014-2858");
  script_bugtraq_id(65678, 67071, 67073);
  script_osvdb_id(103573, 105962, 105963);

  script_name(english:"Grails resources plug-in WEB-INF / META-INF File Disclosure");
  script_summary(english:"Tries to retrieve web.xml / MANIFEST.MF / sitemesh.xml");

  script_set_attribute(attribute:"synopsis", value:
"A Java web application framework in use on the remote web server is
affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server uses a version of Grails, an open source web
application framework for JVM, that is affected by an information
disclosure vulnerability. Specifically, its 'resources' plug-in fails
to restrict access to resources located under an application's
'WEB-INF' and 'META-INF' directories by default. A remote attacker
could leverage this to retrieve the contents of class or configuration
files, such as web.xml, which should be private, including in other
web applications using directory traversal sequences.");
  script_set_attribute(attribute:"see_also", value:"https://twitter.com/Ramsharan065/status/434975409134792704");
  script_set_attribute(attribute:"see_also", value:"http://www.gopivotal.com/security/cve-2014-0053");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2014/Feb/194");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2014/Feb/267");
  script_set_attribute(attribute:"solution", value:
"Upgrade the 'resources' plug-in to 1.2.6, configure it to block access
to resources under 'WEB-INF' and 'META-INF', and redploy the affected
applications.

Alternatively, block access to the 'WEB-INF' and 'META-INF'
directories in a reverse proxy.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:springsource:grails");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:80);


dirs = get_kb_list("www/"+port+"/content/directories");
if (isnull(dirs)) dirs = cgi_dirs();

files = make_list('web.xml');
if (report_paranoia == 2) files = make_list(files, 'MANIFEST.MF', 'sitemesh.xml');


# Loop through possible webapps.
#
# nb: unless thorough_tests is enabled, we'll only scan a couple of directories.
max_apps = 10;

foreach webapp (make_list(dirs))
{
  foreach file (files)
  {
    if ('MANIFEST.MF' == file) url = webapp + '/static/./META-INF/' + file;
    else url = webapp + '/static/./WEB-INF/' + file;

    res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

    if (
      (
        'web.xml' == file &&
        'application/xml' >< res[1] &&
        '<web-app xmlns' >< res[2] &&
        'grails.web.servlet.GrailsDispatcherServlet</servlet-class>' >< res[2]
      ) ||
      (
        'MANIFEST.MF' == file &&
        'Manifest-Version:' >< res[2] &&
        'Grails-Version:' >< res[2]
      ) ||
      (
        'sitemesh.xml' == file &&
        'application/xml' >< res[1] &&
        '<sitemesh>' >< res[2] &&
        'grails.web.sitemesh.GrailsHTMLPageParser' >< res[2]
      )
    )
    {
      if (report_verbosity > 0)
      {
        report =
          '\n' + "Nessus was able to obtain the contents of the '" + file + "' with" +
          '\n' + 'the following request :' +
          '\n' +
          '\n  ' + build_url(qs:url, port:port) +
          '\n';

        if (report_verbosity > 1)
        {
          contents = res[2];

          if (
            !defined_func("nasl_level") ||
            nasl_level() < 5200 ||
            COMMAND_LINE ||
            !isnull(get_preference("sc_version"))
          )
          {
            report +=
              '\n' + 'Here are the contents :' +
              '\n' +
              '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) +
              '\n' + chomp(contents) +
              '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
            security_warning(port:port, extra:report);
          }
          else
          {
            report += '\n' + 'Attached is a copy of the file.' + '\n';
            attachments = make_list();
            attachments[0] = make_array();
            attachments[0]["type"] = "text/plain";
            attachments[0]["name"] = file;
            attachments[0]["value"] = chomp(contents);
            security_report_with_attachments(
              port  : port,
              level : 2,
              extra : report,
              attachments : attachments
            );
          }
        }
        else security_warning(port:port, extra:report);
      }
      else security_warning(port);
      exit(0);
    }
  }
  if (!thorough_tests && --max_apps == 0) break;
}
if (thorough_tests) exit(0, "The web server listening on port "+port+" does not appear to be affected.");
else exit(0, "No vulnerable web apps were found on the web server listening on port "+port+".");
