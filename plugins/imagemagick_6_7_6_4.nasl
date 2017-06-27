#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(59371);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/03/22 14:08:09 $");

  script_cve_id("CVE-2012-1610");
  script_bugtraq_id(52898);
  script_osvdb_id(81024);

  script_name(english:"ImageMagick < 6.7.6-4 profile.c Heap-Based Buffer Overflow");
  script_summary(english:"Checks the version of ImageMagick");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of ImageMagick earlier
than 6.7.6-4 and is, therefore, affected by a heap-based buffer
overflow vulnerability because the fix for CVE-2012-0259 was
incomplete.

The functions 'GetEXIFProperty' and 'SyncImageProfiles' in the file
'magick/profile.c' do not properly validate user-supplied input. This
error can cause the application to crash when processing certain
'EXIF' data.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2012/q2/19");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b592fa61");
  script_set_attribute(attribute:"see_also", value:"http://www.imagemagick.org/script/changelog.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 6.7.6-4 or later.

Note that you may need to manually uninstall the vulnerable version
from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("installed_sw/ImageMagick");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "ImageMagick";
fix = "6.7.6";
fix_build = 4;

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

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, display_version, path);
