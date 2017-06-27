#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91819);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/03/22 14:08:09 $");

  script_cve_id(
    "CVE-2016-5689",
    "CVE-2016-5690",
    "CVE-2016-5691",
    "CVE-2016-10066",
    "CVE-2016-10067",
    "CVE-2016-10069"
  );
  script_bugtraq_id(91283);
  script_osvdb_id(
    140070,
    140071,
    140072,
    149361,
    149362,
    149363
  );

  script_name(english:"ImageMagick 6.x < 6.9.4-5 / 7.x < 7.0.1-7 Multiple DoS");
  script_summary(english:"Checks the version of ImageMagick.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ImageMagick installed on the remote Windows host is 6.x
prior to 6.9.4-5 or 7.x prior to 7.0.1-7. It is, therefore, affected
by multiple denial of service vulnerabilities :

  - A denial of service vulnerability exists in the DCM
    reader due to a NULL pointer dereference flaw that is
    triggered during the handling of photometric
    interpretation or the handling of frames. An
    unauthenticated, remote attacker can exploit this to
    crash processes linked against the library.
    (CVE-2016-5689)

  - A denial of service vulnerability exists in the DCM
    reader due to improper computation of the pixel scaling
    table. An unauthenticated, remote attacker can exploit
    this to crash processes linked against the library.
    (CVE-2016-5690)

  - A denial of service vulnerability exists in the DCM
    reader due to improper validation of pixel.red,
    pixel,green, and pixel.blue. An unauthenticated, remote
    attacker can exploit this to crash processes linked
    against the library. (CVE-2016-5691)

  - Multiple denial of service vulnerabilities exist in
    multiple functions in viff.c due to improper handling of
    a saturation of exceptions. An unauthenticated, remote
    attacker can exploit these issues to crash processes
    linked against the library. (CVE-2016-10066,
    CVE-2016-10067)

  - A denial of service vulnerability exists in the
    ThrowReaderException() function in mat.c due to improper
    handling of frame numbers in a crafted MAT file. An
    unauthenticated, remote attacker can exploit this to
    crash processes linked against the library.
    (CVE-2016-10069)");
  script_set_attribute(attribute:"see_also", value:"http://www.imagemagick.org/script/changelog.php");
  # https://blog.fuzzing-project.org/46-Various-invalid-memory-accesses-in-ImageMagick-WPG,-DDS,-DCM.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b5f3426");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 6.9.4-5 / 7.0.1-7 or later.

Note that you may need to manually uninstall the vulnerable version
from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/24");

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

# determine fix version
if (version =~ "^6\.")
{
  fix = "6.9.4";
  fix_build = 5;
}
else if (version =~ "^7\.")
{
  fix = "7.0.1";
  fix_build = 7;
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, display_version, path);

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
