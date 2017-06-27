#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44342);
  script_version("$Revision: 1.9 $");
 script_cvs_date("$Date: 2017/04/25 20:29:05 $");

  script_bugtraq_id(37900);
  script_osvdb_id(61963);
  script_xref(name:"Secunia", value:"38217");

  script_name(english:"SAP BusinessObjects 'HappyAxis2.jsp' Information Disclosure");
  script_summary(english:"Checks if the page is leaking info");

  script_set_attribute(attribute:"synopsis", value:"A web application running on the remote host is leaking information.");
  script_set_attribute(
    attribute:"description",
    value:
"The SAP BusinessObjects installation on the remote web server is
leaking information via '/BusinessProcessBI/axis2-web/HappyAxis.jsp'.
This page contains debugging information such as local file paths,
operating system version, and Java version.

A remote attacker could use this information to mount further
attacks.

This version of BusinessObjects reportedly has several other
vulnerabilities, though Nessus has not checked for those issues."
  );
   # http://web.archive.org/web/20100403074821/http://www.procheckup.com/vulnerability_manager/vulnerabilities/pr09-02
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c9cfae68");
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/fulldisclosure/2010/Jan/572"
  );
  script_set_attribute(attribute:"solution", value:"Restrict access to this web page.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  # ? not sure if a patch has been published ?

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:businessobjects");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("sap_bobj_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 6405, 8080);
  script_require_keys("www/sap_bobj");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:6405);
install = get_install_from_kb(appname:'sap_bobj', port:port);
if (isnull(install))
  exit(1, "SAP BusinessObjects install not found in KB for port " + port);

url = install['dir']+'/BusinessProcessBI/axis2-web/HappyAxis.jsp';
res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

if (
  '<title>Axis2 Happiness Page</title>' >< res[2] &&
  'Examining webapp configuration' >< res[2]
)
{
  if (report_verbosity > 0)
  {
    trailer = NULL;

    if (report_verbosity > 1)
    {
      info = '';
      patterns = make_array(
        'os.name</th><td[^>]+>([^<]+)&nbsp;</td>', 'Operating System',
        'java.runtime.version</th><td[^>]+>([^<]+)&nbsp;</td>', 'JRE Version',
        'os.arch</th><td[^>]+>([^<]+)&nbsp;</td>', 'Architecture',
        'at ([^<]+)\\\\java\\\\server\\\\work\\\\', 'Install Path'
      );

      foreach pat (keys(patterns))
      {
        match = eregmatch(string:res[2], pattern:pat);
        if (match) info += '  ' + patterns[pat] + ': ' + match[1] + '\n';
      }

      # If any info was extracted, make sure it makes it into the report
      if (info != '')
        trailer = 'Which displays information such as :\n\n' + info;
    }

    report = get_vuln_report(items:url, port:port, trailer:trailer);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "The BusinessObjects page at "+build_url(qs:url, port:port)+" is not affected.");

