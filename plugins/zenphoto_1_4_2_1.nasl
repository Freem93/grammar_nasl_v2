#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58454);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/13 21:07:15 $");

  script_cve_id("CVE-2012-0993", "CVE-2012-0994", "CVE-2012-0995");
  script_bugtraq_id(51916);
  script_osvdb_id(78979, 78980, 78981, 78982);

  script_name(english:"Zenphoto < 1.4.2.1 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Zenphoto");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of Zenphoto earlier than 1.4.2.1
that is affected by multiple vulnerabilities :

  - An input validation error in the file
    'zp-core/zp-extensions/viewer_size_image.php' can allow
    arbitrary PHP code to be injected via the value of the
    cookie 'viewer_size_image_saved cookie'. Note that the
    plugin 'viewer_size_image' must be enabled for this
    vulnerability to be exploited. (CVE-2012-0993)

  - An input validation error in the file
    'zp-core/admin-albumsort.php' can allow SQL injection
    attacks via the 'sortableList' parameter.
    (CVE-2012-0994)

  - Multiple cross-site scripting vulnerabilities exist
    in the following (CVE-2012-0995) :

    - 'zp-core/admin.php' via the 'msg' parameter
    - 'zp-core/admin.php' and undefined urls by appending
      malicious code to the end of the url
    - 'zp-core/admin-edit.php' via the 'album' parameter");
  script_set_attribute(attribute:"see_also", value:"https://www.htbridge.ch/advisory/HTB23070");
  script_set_attribute(attribute:"see_also", value:"http://www.zenphoto.org/news/zenphoto-1.4.2.1");
  script_set_attribute(attribute:"see_also", value:"http://www.zenphoto.org/trac/changeset/8994");
  script_set_attribute(attribute:"see_also", value:"http://www.zenphoto.org/trac/changeset/8995");
  script_set_attribute(attribute:"solution", value:"Upgrade to Zenphoto version 1.4.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Zenphoto 1.4.2 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zenphoto:zenphoto");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("zenphoto_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/zenphoto", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port    = get_http_port(default:80, php:TRUE);
install = get_install_from_kb(appname:"zenphoto", port:port, exit_on_fail:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

dir         = install['dir'];
install_url = build_url(port:port,qs:dir);
version     = install['ver'];

if (version == UNKNOWN_VER) exit(1, "The version of Zenphoto located at "+install_url+" could not be determined.");

fixed_version = '1.4.2.1';
fixed_build   = '9138';

# Separate the build number
pieces = split(version, sep:" ", keep:FALSE);
if (!isnull(pieces[0]))
  version = pieces[0];
if (!isnull(pieces[1]))
{
  build = pieces[1];
  version_ui = strcat(version, " Build ", build);
}
else
{
  build = NULL;
  version_ui = version;
}

# Check if versions are the same;
# if so, check if we have a build
# number to compare with. Exit if not.
if (version == fixed_version && isnull(build))
  exit(1, "The build number of Zenphoto version "+version+" located at "+install_url+" could not be determined and is needed for comparison.");

# If versions are the same and build
# is null, it won't play a part, so
# set it to text for report output.
if (isnull(build)) build = 'Unknown';

ver = split(version,sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

if (
  (
    ver[0] < 1 ||
    (
      ver[0] == 1 &&
      (
        (ver[1] < 4) ||
        (ver[1] == 4 && ver[2] < 2) ||
        (ver[1] == 4 && ver[2] == 2 && ver[3] < 1)
      )
    )
  ) ||
  (version == fixed_version && build < fixed_build)
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version_ui +
      '\n  Fixed version     : ' + fixed_version + ' Build ' + fixed_build +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The Zenphoto "+version_ui+" install at "+install_url+" is not affected.");
