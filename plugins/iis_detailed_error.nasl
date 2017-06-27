#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(58363);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/01/29 21:04:36 $");

  script_name(english:"IIS Detailed Error Information Disclosure");
  script_summary(english:"Checks for detailed error responses.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server has an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Microsoft IIS web server is improperly configured to
deliver detailed error messages. These detailed error messages may
contain confidential diagnostic information, such as the file system
paths to hosted content and logon information.");
  # http://www.iis.net/learn/troubleshoot/diagnosing-http-errors/how-to-use-http-detailed-errors-in-iis
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?90427c4a");
  # http://blogs.msdn.com/b/rakkimk/archive/2007/05/25/iis7-how-to-enable-the-detailed-error-messages-for-the-website-while-browsed-from-for-the-client-browsers.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6006cd8");
  script_set_attribute(attribute:"see_also", value:"http://www.iis.net/ConfigReference/system.webServer/httpErrors");
  script_set_attribute(attribute:"solution", value:
"Configure the IIS server to deliver custom rather than detailed error
messages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/iis");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port, exit_on_fail:TRUE);
if ("IIS/" >!< banner) exit(0, "The web server listening on port "+port+" does not look like IIS.");

foreach dir (cgi_dirs())
{
  filename = rand() + '.html';
  url = dir + "/" + filename;

  res = http_send_recv3(
    method:"GET",
    item:url,
    port:port,
    fetch404: TRUE,
    exit_on_fail:TRUE
  );

  if (
    (
      '<legend>Detailed Error Information</legend>' >< res[2] ||
      'IIS Web Core' >< res[2]
    ) &&
    'Physical Path' >< res[2]
  )
  {
    set_kb_item(name:"www/"+port+"/iis_detailed_errors", value:TRUE);

    # Grab version info for use in other plugin(s)
    ver = eregmatch(
      pattern : '<title>IIS ([0-9\\.]+) Detailed Error.+</title>($|[^\n])',
      string  : res[2]
    );
    if (!empty_or_null(ver))
    {
      set_kb_item(name:"www/"+port+"/iis_version", value:ver[1]);
      set_kb_item(name:"www/"+port+"/iis_version_from", value:url);
    }

    # nb: Detailed errors are enabled by default for localhost so
    #     only report them if we're being paranoid.
    if (islocalhost() && report_paranoia < 2) exit(0, "The IIS server listening on port "+port+" returns detailed error messages locally.");

    if (report_verbosity > 0)
    {
      report =
        '\n' + 'Nessus was able to obtain a detailed error message using the following' +
        '\n' + 'URL :' +
        '\n' +
        '\n  ' + build_url(qs:url, port:port) +
        '\n';
      if (report_verbosity > 1)
      {
        report += '\n' + 'Here is the message :\n' +
          '\n' +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
          res[2] +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
exit(0, "The IIS server on port " + port + " is not affected.");
