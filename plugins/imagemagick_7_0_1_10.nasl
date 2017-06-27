#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91763);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/03/22 14:08:09 $");

  script_cve_id(
    "CVE-2016-10050",
    "CVE-2016-10060",
    "CVE-2016-10061",
    "CVE-2016-10062"
  );
  script_bugtraq_id(
    95185,
    95207,
    95208,
    95209
  );
  script_osvdb_id(
    139655,
    139656,
    149356,
    149357,
    149358
  );

  script_name(english:"ImageMagick 7.x < 7.0.1-10 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of ImageMagick.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of ImageMagick installed that is
7.x prior to 7.0.1-10. It is, therefore, affected by the following
vulnerabilities :

  - An overflow condition exists in the ReadRLEImage()
    function in rle.c due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this, by convincing a user to open a 
    specially crafted RLE image, to cause a heap-based
    buffer overflow, resulting in a denial of service
    condition or the execution of arbitrary code.
    (CVE-2016-10050)

  - An unspecified flaw exists in the ConcatenateImages()
    function in magick-cli.c that is triggered when handling
    return values. An unauthenticated, remote attacker can
    exploit this to have an unspecified impact.
    (CVE-2016-10060)

  - An unspecified flaw exists in the ReadGROUP4Image()
    function in tiff.c that is triggered when handling
    return values. An unauthenticated, remote attacker can
    exploit this to have an unspecified impact.
    (CVE-2016-10061)
    
  - An unspecified flaw exists in the ReadGROUP4Image()
    function in tiff.c that is triggered when handling
    fwrite errors. An unauthenticated, remote attacker can
    exploit this to have an unspecified impact.
    (CVE-2016-10062)

  - A flaw exists in pes.c due to improper handling of PES
    blocks. An unauthenticated, remote attacker can exploit
    this to cause a process linked against the library to
    crash, resulting in a denial of service condition.
    (VulnDB 139656)");
  script_set_attribute(attribute:"see_also", value:"http://www.imagemagick.org/script/changelog.php");
  script_set_attribute(attribute:"see_also", value:"https://github.com/ImageMagick/ImageMagick/issues/213");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 7.0.1-10 or later.

Note that you may need to manually uninstall the vulnerable version
from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/22");

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
fix = "7.0.1";
fix_build = 10;

# Get installs
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
display_version = install['display_version'];
version         = install['version'];
build           = install['build'];
path            = install['path'];

vuln = FALSE;

display_fix = fix + "-" + fix_build;

if (version !~ "^7\.") audit(AUDIT_NOT_INST, "ImageMagick 7.x");

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
