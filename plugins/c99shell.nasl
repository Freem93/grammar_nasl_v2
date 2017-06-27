#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46349);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/21 20:34:20 $");

  script_name(english:"c99shell Backdoor Detection");
  script_summary(english:"Looks for c99shell script");

  script_set_attribute(attribute:"synopsis", value:"The remote web server contains a PHP backdoor script.");
  script_set_attribute(
    attribute:"description",
    value:
"At least one instance of c99shell (or a derivative, such as c100 or
Locus7Shell) is hosted on the remote web server.  This is a PHP script
that acts as a backdoor and provides a convenient set of tools for
attacking the affected host."
  );
  script_set_attribute(attribute:"see_also", value:"http://vil.nai.com/vil/content/v_136948.htm");
  # http://www.sophos.com/en-us/threat-center/threat-analyses/viruses-and-spyware/PHP~C99Shell-A.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?12540cda");
  script_set_attribute(attribute:"solution",
    value:
"Remove any instances of the script and conduct a forensic examination
to determine how it was installed as well as whether other unauthorized
changes were made."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, php:TRUE);


# Loop through files.
#
# nb: By default, we'll look for it as 'c99.php', 'c99shell.php', and
#     'c100.php' and, if the "Perform thorough tests" setting is enabled, some other
#     common variants. Still, the script can be named anything and
#     won't necessarily be found by webmirror.nasl so a remote check
#     is not likely to be 100% effective.
files = make_list(
  'c99.php',
  'c99shell.php',
  'c100.php'
);
if (thorough_tests)
{
  files = make_list(
    files,
    'index.php',
    'ch99.php'
  );
}

dirs = get_kb_list("www/"+port+"/content/directories");
if (isnull(dirs)) dirs = cgi_dirs();

info = "";
foreach dir (list_uniq("", dirs))
{
  foreach file (files)
  {
    url = dir + '/' + file;
    res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);
    if (
      res[2] &&
      (
        ('<b>C99Shell v.' >< res[2] || '<b>--[c99shell v.' >< res[2]) &&
        egrep(pattern:'<a href="\\?act=cmd[^"]+"><b>Command execute', string:res[2])
      ) ||
      (
        ('Locus7Shell</title>' || '<b>--[ x2300 Locus7Shell v.' >< res[2]) &&
        egrep(pattern:'<form action="\\?act=cmd"[^>]+><input type=hidden name=act value="cmd">', string:res[2])
      )
    )
    {
      info += '  - ' + build_url(port:port, qs:file) + '\n';

      if (!thorough_tests) break;
    }
  }
  if (info && !thorough_tests) break;
}


# Report findings.
if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 1) s = 's';
    else s = '';

    report = '\n' +
      'Nessus discovered the following instance' + s + ' of c99shell :\n' +
      '\n' +
      info;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
else exit(0, "c99shell was not found on the web server listening on port "+port+".");
