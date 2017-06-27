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
# Mandriva Linux Security Advisory MDVA-2008:090.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(36877);
  script_version ("$Revision: 1.8 $"); 
  script_cvs_date("$Date: 2012/10/04 19:39:05 $");

  script_name(english:"MDVA-2008:090 : nautilus");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"A regression was introduced in the Mandriva Linux GNOME package while
fixing CD-ROM drives ejecting when using the hardware button when the
CD-ROM drive was present in the system fstab. This regression caused
an error popup to appear when using the eject hardware button on
CD-ROM drives not present in the system fstab.

This package update fixes this regression and includes many stability
and bug fixes, as well as translation updates from the GNOME 2.22.2
release of nautilus and gvfs.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2008:090");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/23");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Mandriva Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");

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

if (rpm_check(reference:"gvfs-0.2.4-2.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libgvfs0-0.2.4-2.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libgvfs-devel-0.2.4-2.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libnautilus1-2.22.3-2.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libnautilus-devel-2.22.3-2.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"nautilus-2.22.3-2.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"gvfs-0.2.4-2.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64gvfs0-0.2.4-2.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64gvfs-devel-0.2.4-2.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64nautilus1-2.22.3-2.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64nautilus-devel-2.22.3-2.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"nautilus-2.22.3-2.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;


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
