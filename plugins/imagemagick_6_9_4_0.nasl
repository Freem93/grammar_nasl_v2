#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91232);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/03/22 14:08:09 $");

  script_bugtraq_id(90611);
  script_osvdb_id(
    138108,
    138399,
    138441,
    138442
  );
  script_xref(name:"EDB-ID", value:"39766");

  script_name(english:"ImageMagick 6.x < 6.9.4-0 / 7.x < 7.0.1-2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of ImageMagick.");

  script_set_attribute(attribute:"synopsis", value:
"The application installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ImageMagick installed on the remote Windows host is 6.x
prior to 6.9.4-0 or 7.x prior to 7.0.1-2. It is, therefore, affected
by the following vulnerabilities :

  - A flaw exists in the imagick Extension that allows an
    unauthenticated, remote attacker to bypass the
    'disable_functions' setting, resulting in the execution
    of arbitrary commands or code. (VulnDB 138108)

  - A buffer overflow condition exists in the
    DrawStrokePolygon() function within file magick/draw.c
    due to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (VulnDB 138399)

  - An out-of-bounds read error exists in the
    PushShortPixel() function within file coders/psd.c when
    handling a specially crafted PSD file. An
    unauthenticated, remote attacker can exploit this to
    disclose sensitive information or cause a denial of
    service condition. (VulnDB 138441)

  - A buffer overflow condition exists in the
    WritePixelCachePixels() function within file cache.c due
    to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted PICT file, to cause a denial of
    service condition or the execution of arbitrary code.
    (VulnDB 138442)");
  script_set_attribute(attribute:"see_also", value:"http://www.imagemagick.org/script/changelog.php");
  # https://blog.fuzzing-project.org/45-ImageMagick-heap-overflow-and-out-of-bounds-read.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81716ecb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 6.9.4-0 / 7.0.1-2 or later.

Note that you may need to manually uninstall the vulnerable version
from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("installed_sw/ImageMagick");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "ImageMagick";

# Get installs
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
display_version = install['display_version'];
version         = install['version'];
build           = install['build'];
path            = install['path'];

vuln = FALSE;

if (version =~ "^6\.")
{
  fix = "6.9.4";
  fix_build = 0;
}
else if (version =~ "^7\.")
{
  fix = "7.0.1";
  fix_build = 2;
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, display_version, path);

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
