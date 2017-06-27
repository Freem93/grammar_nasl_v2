#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48243);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2014/10/31 20:03:29 $");

  script_name(english:"PHP Version");
  script_summary(english:"Obtains the version of the remote PHP install");
  script_set_attribute(attribute:"synopsis", value:"It is possible to obtain the version number of the remote PHP install.");
  script_set_attribute(attribute:"description", value:
"This plugin attempts to determine the version of PHP available on the
remote web server.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "phpinfo.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("backport.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);
source  = NULL;
version = NULL;
installs = make_array();

srv_hdr = http_server_header(port:port);
srv_hdr = chomp(srv_hdr);

banner = get_http_banner(port:port);
if (!isnull(banner))
{
  # Identify the source header line and version info.
  pat = '^(Server|X-Powered-By):.*PHP/([0-9][^ ]+)';

  matches = egrep(string:banner, pattern:pat);
  if (matches)
  {
    foreach line (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:line);
      if (!isnull(item))
      {
        # nb: we just take the first one.
        source = line;
        version = item[2];
        break;
      }
    }
  }

  if (!isnull(version))
  {
    # Determine if it's been backported.
    get_backport_banner(banner:banner);
    if (!backported) get_php_version(banner:banner);

    if (backported)
      set_kb_item(name: 'www/php/'+port+'/'+version+'/backported', value:TRUE);
    else if (srv_hdr =~ '^Apache$')
      set_kb_item(name: 'www/php/'+port+'/'+version+'/backported', value:TRUE);

    #reporting
    installs[version] += source + ', ';
  }
}

# Check for version info from phpinfo.nasl and extract unique values
vers = get_kb_list('www/phpinfo/'+port+'/version/*');
if (!isnull(vers))
{
  foreach ver (list_uniq(keys(vers)))
  {
    backported = FALSE;
    version = ereg_replace(
      pattern : 'www/phpinfo/[0-9]+/version/',
      replace : '',
      string  : ver
    );
    dir = eregmatch(pattern: "under (.+)", string:vers[ver]);
    if (!isnull(dir)) source = dir[1];

    # Is version backported?
    if (version =~ "[0-9]+")
    {
      banner = "X-Powered-By: PHP/" + version;
      get_backport_banner(banner:banner);
      if (!backported) get_php_version(banner:banner);
    }

    if (backported)
      set_kb_item(name:'www/php/'+port+'/'+version+'/backported', value:TRUE);
    else if (srv_hdr =~ '^Apache$')
      set_kb_item(name:'www/php/'+port+'/'+version+'/backported', value:TRUE);

    #reporting
    installs[version] += source + ', ';
  }
}
if (isnull(source))
  exit(0, "There is no mention of PHP in the 'Server' and/or 'X-Powered-By' response headers or from a phpinfo() page from the web server listening on port "
+port+".");

# Sort unique versions and add to KB / report output
report = '\nNessus was able to identify the following PHP version ' +
  'information :\n';

foreach version (sort(keys(installs)))
{
  set_kb_item(
      name  : 'www/php/'+port+'/version',
      value : version + ' under ' + installs[version]
    );
  report += '\n  Version : ' + version + '\n';
  sources = split(installs[version],sep:', ', keep:FALSE);

  foreach source (sort(sources))
  {
    report += '  Source  : ' + source + '\n';
  }
}

if (report_verbosity > 0)
{
  security_note(port:port, extra:report);
}
else security_note(port);
