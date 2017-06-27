#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32318);
  script_version("$Revision: 1.14 $");

  script_name(english:"Web Site Cross-Domain Policy File Detection");
  script_summary(english:"Checks for the file crossdomain.xml");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a 'crossdomain.xml' file." );
 script_set_attribute(attribute:"description", value:
"The remote web server contains a cross-domain policy file.  This is a
simple XML file used by Adobe's Flash Player to allow access to data
that resides outside the exact web domain from which a Flash movie
file originated." );
 # http://www.adobe.com/devnet/flashplayer/articles/cross_domain_policy.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?577e066f" );
 script_set_attribute(attribute:"see_also", value:"http://kb2.adobe.com/cps/142/tn_14213.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74a6a9a5" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50ee6db2" );
 script_set_attribute(attribute:"solution", value:
"Review the contents of the policy file carefully.  Improper policies,
especially an unrestricted one with just '*', could allow for cross-
site request forgery and cross-site scripting attacks against the web
server." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/05/15");
 script_cvs_date("$Date: 2017/05/16 19:35:38 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# Loop through directories.
#
# nb: only look in the root directory if CGI scanning is disabled.
if (get_kb_item("Settings/disable_cgi_scanning")) dirs = make_list("");
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to retrieve the file.
  url = string(dir, "/crossdomain.xml");

  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # Report it if one was found.
  if ("<cross-domain-policy>" >< tolower(res))
  {
    if (report_verbosity)
    {
      url = build_url(port: port, qs: url);

      report = string(
        "\n",
        "Nessus was able to obtain a cross-domain policy file from the remote\n",
        "host using the following URL :\n",
        "\n",
        "  ", url, "\n"
      );
      if (report_verbosity > 1)
      {
        report = strcat(
          report,
          '\n',
          'Here are its contents :\n',
          '\n',
          str_replace(string: res, find: '><', replace: '>\n<')
        );
      }
      security_note(port:port, extra:report);
    }
    else security_note(port);

    if (!thorough_tests) exit(0);
  }
}
