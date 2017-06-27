#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(55640);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_name(english:"SQL Dump Files Disclosed via Web Server");
  script_summary(english:"Looks for SQL dumps accessible via HTTP");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts publicly accessible SQL dump files.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts publicly available files that contain SQL
instructions.  These files are most likely database dumps and may
contain sensitive information.");
  script_set_attribute(attribute:"solution", value:
"Make sure that such files do not contain any confidential or
otherwise sensitive information and that they are only accessible to
those with valid credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/21");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('http.inc');

if (
  get_kb_item("Settings/disable_cgi_scanning") &&
  !get_kb_item("Settings/enable_web_app_tests")
) exit(0, "Settings/disable_cgi_scanning=1 and Settings/enable_web_app_tests=0");


port = get_http_port(default:80);

files = get_kb_list('www/'+port+'/content/extensions/sql');
if (isnull(files)) exit(0, 'No SQL files were detected on the remote host.');

# Clear the cookiejar in case we have credentials.
clear_cookiejar();

max_files = 10;
n = 0;
report = "";
foreach f (make_list(files))
{
  res = http_send_recv3(method:"GET", item:f, port:port, exit_on_fail:TRUE);
  if (
    egrep(string:res[2], pattern:'CREATE +TABLE +(IF +NOT +EXISTS)? *[^ ]+ +\\(', icase:TRUE) ||
    egrep(string:res[2], pattern:'INSERT( +INTO)? +TABLE +(IF +NOT +EXISTS)? *[^ ]+ +\\(', icase:TRUE)
  )
  {
    report += '  - ' + f + '\n';

    n++;
    if (!thorough_tests && n > max_files) break;
  }
}

if (report)
{
  if (report_verbosity > 0)
  {
    report = 
      '\nThe following SQL files are available on the remote server :' +
      '\n' +
      '\n' + report;
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, 'No publicly accessible SQL dumps were found on the web server listening on port '+port+'.');
