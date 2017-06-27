#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57700);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/10/17 10:40:08 $");

  script_cve_id("CVE-2011-4166", "CVE-2011-4167", "CVE-2011-4168", "CVE-2011-4169");
  script_bugtraq_id(51174);
  script_osvdb_id(78015, 78016, 78017, 78018);

  script_name(english:"HP Managed Printing Administration < 2.6.4 Multiple Vulnerabilities");
  script_summary(english:"Checks version of HP Managed Printing Administration");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an ASP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server is hosting a version of HP Managed Printing
Administration earlier than 2.6.4.  As such, it is potentially
affected by the following vulnerabilities :

  - Multiple directory traversal, arbitrary file-deletion,
    and file-creation vulnerabilities affect the
    'MPAUploader.Uploader.1.UploadFiles()' function.
    (CVE-2011-4166)

  - A remote-code execution vulnerability affects the
    'MPAUploader.dll' file which can be exploited via the
    'filename' parameter of the 'Default.asp' script.
    (CVE-2011-4167)

  - Multiple directory traversal, arbitrary file-deletion,
    and file-creation vulnerabilities affect the
    '/hpmpa/jobDelivery/Default.asp' script.
    (CVE-2011-4168)

  - Input via the 'img_id' parameter of the
    'imglist\imgselect\Default.asp',
    'imgmap\bgselect\Default.asp', and
    'imgmpa\imgselect\Default.asp' scripts can be
    manipulated to perform SQL injection.
    (CVE-2011-4169)");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-352/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-353/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-354/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-001/");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?336f98c9");
  script_set_attribute(attribute:"solution", value:"Upgrade to HP Managed Printing Administration 2.6.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-073");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
script_set_attribute(attribute:"metasploit_name", value:'HP Managed Printing Administration jobAcct Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:managed_printing_administration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("hp_managed_printing_administration_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/hp_managed_printing_administration");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);
install = get_install_from_kb(appname:'hp_managed_printing_administration', port:port, exit_on_fail:TRUE);

if (isnull(install['ver']) || install['ver'] == UNKNOWN_VER)
  exit(1, 'The version of HP Managed Printing Administration on port ' + port + ' is unknown.');

# Versions < 2.6.4 are affected
version = install['ver'];

if (ver_compare(ver:version, fix:'2.6.4') == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + build_url(port:port, qs:install['dir']) +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.6.4 \n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, 'HP Managed Printing Administration ' + version + ' is installed and thus not affected.');
