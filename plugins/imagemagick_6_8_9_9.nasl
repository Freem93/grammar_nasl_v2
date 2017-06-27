#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78892);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/03/22 14:08:09 $");

  script_cve_id(
    "CVE-2014-8354",
    "CVE-2014-8355",
    "CVE-2014-8561",
    "CVE-2014-8562"
  );
  script_bugtraq_id(70802, 70830, 70837, 70839);
  script_osvdb_id(113934, 113923, 113932, 113933, 113946);

  script_name(english:"ImageMagick < 6.8.9-9 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of ImageMagick");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of ImageMagick prior to
version 6.8.9-9. It is, therefore, affected by the following
vulnerabilities :

  - An out-of-bounds read error exist in the function
    'CloneImage' within file 'image.c' that can allow
    application crashes or information disclosure.
    (CVE-2014-8354)

  - An out-of-bounds read error exist in the function
    'ReadPCXImage' within file 'coders/pcx.c' that can
    allow application crashes or information disclosure.
    (CVE-2014-8355)

  - An error exists in the function 'DeleteImageProfile'
    related to image processing that can allow denial of
    service attacks. (CVE-2014-8561)

  - An out-of-bounds read error exists in the 'ReadDCMImage'
    function within file 'coders/dcm.c' that can allow
    application crashes or information disclosure.
    (CVE-2014-8562)

  - An off-by-one error exists related to '8BIM' handling
    that can allow an attacker to have an unspecified
    impact. (VulnDB 113934)");
  script_set_attribute(attribute:"see_also", value:"http://www.imagemagick.org/script/changelog.php");
  script_set_attribute(attribute:"see_also", value:"http://www.openwall.com/lists/oss-security/2014/10/29/5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 6.8.9-9 or later.

Note that you may need to manually uninstall the vulnerable version
from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("installed_sw/ImageMagick");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "ImageMagick";
fix = "6.8.9";
fix_build = 9;

# Get installs
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
display_version = install['display_version'];
version         = install['version'];
build           = install['build'];
path            = install['path'];

vuln = FALSE;

display_fix = fix + "-" + fix_build;

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
  vuln = TRUE;

if ((ver_compare(ver:version, fix:fix, strict:FALSE) == 0)  &&
    build < fix_build
   )
  vuln = TRUE;

if (vuln)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  items = make_array("Installed version", display_version,
                     "Fixed version", display_fix,
                     "Path", path
                    );

  order = make_list("Path", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, display_version, path);
