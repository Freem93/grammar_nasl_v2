#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(83346);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/28 16:42:41 $");

  script_name(english:".bash_history Files Disclosed via Web Server");
  script_summary(english:"Checks for common commands that may be present in a typical .bash_history.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a publicly accessible .bash_history file.");
  script_set_attribute(attribute:"description", value:
"Nessus has detected that the remote web server hosts publicly
available files whose contents are indicative of a typical bash
history. Such files may contain sensitive information that should not
be disclosed to the public.");
  script_set_attribute(attribute:"solution", value:
"Make sure that such files do not contain any confidential or otherwise
sensitive information, and that the files are only accessible to those
with valid credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('http.inc');

port = get_http_port(default:80);

files = get_kb_list('www/'+port+'/content/extensions/bash_history');
if (!isnull(files)) files = make_list(files, "/.bash_history");
else files = make_list("/.bash_history");

# Clear the cookiejar in case we have credentials.
clear_cookiejar();

max_files = 10;
n = 0;
report = "";
cmds = '^(ls|cd|echo|cp|mv|grep|pwd).*$';

foreach f (files)
{
  res = http_send_recv3(method:"GET", item:f, port:port, exit_on_fail:TRUE);

  # Content type should be text/plain
  headers = parse_http_headers(status_line:res[0], headers:res[1]);
  if (!empty_or_null(headers))
  {
    if (headers['content-type'] !~ "text\/plain")
      continue;
  }
  else continue;

  if (preg(string:res[2], pattern:cmds, multiline:TRUE))
  {
    report += '  - ' + f + '\n';

    n++;
    if (!thorough_tests && n > max_files) break;
  }
}

# If thorough check each of the directories
if (thorough_tests)
{
  foreach dir (cgi_dirs())
  {
    # Skip doc root since we covered up above already
    if (dir == "")
     continue;

    f = dir + "/.bash_history";
    res = http_send_recv3(method:"GET", item:f, port:port, exit_on_fail:TRUE);

    # Content type should be text/plain
    headers = parse_http_headers(status_line:res[0], headers:res[1]);
    if (!empty_or_null(headers))
    {
      if (headers['content-type'] !~ "text\/plain")
        continue;
    }
    else continue;

    if (egrep(string:res[2], pattern:cmds))
      report += '  - ' + f + '\n';
  }
}

if (report)
{
  report =
    '\nThe following .bash_history files are available on the remote server :' +
    '\n' +
    '\n' + report;
  security_report_v4(port:port, severity : SECURITY_WARNING, extra:report);
  exit(0);
}
else exit(0, 'No publicly accessible .bash_history files were found on the web server listening on port '+port+'.');
