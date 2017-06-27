#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(46803);
  script_version("$Revision: 1.5 $");
  script_osvdb_id(12184);
  script_cvs_date("$Date: 2015/10/21 20:34:20 $");


  script_name(english:"PHP expose_php Information Disclosure");
  script_summary(english:"Detects if PHP's expose_php Configuration Option is Enabled");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The configuration of PHP on the remote host allows disclosure of
sensitive information."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The PHP install on the remote server is configured in a way that
allows disclosure of potentially sensitive information to an attacker
through a special URL.  Such a URL triggers an Easter egg built into
PHP itself. 

Other such Easter eggs likely exist, but Nessus has not checked for
them."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.0php.com/php_easter_egg.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/webappsec/2004/q4/324"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"In the PHP configuration file, php.ini, set the value for
'expose_php' to 'Off' to disable this behavior.  Restart the web
server daemon to put this change into effect."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_attribute(attribute:"vuln_publication_date",value:"2004/11/28");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/06/03");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:php:php");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_dependencie("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include('http.inc');

port = get_http_port(default:80, embedded:0, php:TRUE);

exploit = '/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000';

urls = get_kb_list('www/'+port+'/content/extensions/php*');

if (isnull(urls))
{
  urls = make_list
    (
      '/index.php',
      '/index.php3',
      '/default.php',
      '/default.php3'
    );
  if (!thorough_tests) urls = make_list(urls[0]);
}
else
{
  urls = make_list(urls);
  urls = make_list(urls[0]);
}

foreach url (urls)
{
  url = url + exploit;
  r = http_send_recv3(
    port          : port,
    item          : url,
    method        : 'GET',
    exit_on_fail  : TRUE
  );

  if (
    '<h1>PHP Credits</h1>' >< r[2] &&
    '<th colspan="2">Module Authors</th>' >< r[2] &&
    '<th colspan="2">PHP Documentation</th>' >< r[2]
  )
  {
    if (report_verbosity > 0)
    {
      report = '\n' +
        'Nessus was able to verify the issue using the following URL :\n' +
        '\n' +
        '  ' + build_url(qs:url, port:port) + '\n';
      security_warning(port: port, extra: report);
    }
    else security_warning(port: port);
    exit(0);
  }
}
exit(0, "The web server on port " + port + " is not affected.");
