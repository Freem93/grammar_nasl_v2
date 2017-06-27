#%NASL_MIN_LEVEL 99999
# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a security fix.
#
# Disabled on 2012/09/06.
#

#
# (C) Tenable Network Security, Inc.
#
# This script was automatically generated from
# Mandriva Linux Security Advisory MDVA-2009:271.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(48031);
  script_version("$Revision: 1.6 $"); 
  script_cvs_date("$Date: 2012/10/04 19:39:08 $");

  script_name(english:"MDVA-2009:271 : k3b");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"Mandriva 2010 includes k3b 1.68 (alpha3) and the stable release won't
be ready before a long time, this update introduces the Aplha4
version, with lot's of bugfixes and some new features including:

New features

* Added close buttons on project tabs (159751) * Added support for
new libmpcdec API (214149)

Bugfixes

* Crash at the beginning of burning (204333) * Crash during DVD
ripping (207958) * Crash right after burn (195436) * Crash during
Audio CD ripping (198015) * Crash at the beginning of ripping Audio
CD with data tracks (186555) * Crash at the beginning of burning
cue/bin image (190775) * Fixed various typos in UI (208401, 209512) *
Fixed potential aliasing issues (210890) * Show only one entry on the
task list even when dialog window is opened (211680) * Show correct
size when project contains invalid links (212609) * Show correct
elapsed time when burning over midnight (211604) * Added timeout when
checking version number and features of executable (212582) * Fixed
visually endless busy status when opening an empty folder (113649) *
Burning double-layer DVDs should be possible again (214115)

This bug also fixes an error in the migration process from 2009.0 to
2010.0 (bug #56493)");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2009:271");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/30");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/07/30");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Mandriva Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a security fix.");


include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/Mandrake/release")) exit(0, "The host is not running Mandrake Linux.");
if (!get_kb_item("Host/Mandrake/rpm-list")) exit(1, "Could not get the list of packages.");

flag = 0;

if (rpm_check(reference:"k3b-1.69.0-0.alpha4.1.2mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"k3b-devel-1.69.0-0.alpha4.1.2mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libk3b6-1.69.0-0.alpha4.1.2mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libk3bdevice6-1.69.0-0.alpha4.1.2mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"k3b-1.69.0-0.alpha4.1.2mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"k3b-devel-1.69.0-0.alpha4.1.2mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64k3b6-1.69.0-0.alpha4.1.2mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64k3bdevice6-1.69.0-0.alpha4.1.2mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else 
{
  exit(0, "The host is not affected.");
}
