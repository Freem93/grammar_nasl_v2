#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(38951);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/03/22 14:08:09 $");

  script_cve_id("CVE-2009-1882");
  script_bugtraq_id(35111);
  script_osvdb_id(54729);
  script_xref(name:"Secunia", value:"35216");

  script_name(english:"ImageMagick < 6.5.2-9 magick/xwindow.c XMakeImage() Function TIFF File Handling Overflow");
  script_summary(english:"Checks the version of ImageMagick");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
an integer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of ImageMagick earlier
than 6.5.2-9.  Such versions reportedly fail to properly handle
malformed 'TIFF' files in the 'XMakeImage()' function.  If an attacker
can trick a user on the remote host into opening a specially crafted
file using the affected application, he can leverage this flaw to
execute arbitrary code on the remote host subject to the user's
privileges.");
  script_set_attribute(attribute:"see_also", value:"http://mirror1.smudge-it.co.uk/imagemagick/www/changelog.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 6.5.2-9 or later.

Note that you may need to manually uninstall the vulnerable version
from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("installed_sw/ImageMagick");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "ImageMagick";
fix = "6.5.2";
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
