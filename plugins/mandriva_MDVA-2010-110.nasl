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
# Mandriva Linux Security Advisory MDVA-2010:110.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(48091);
  script_version("$Revision: 1.6 $"); 
  script_cvs_date("$Date: 2012/10/04 19:39:09 $");

  script_name(english:"MDVA-2010:110 : dbus");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"This update makes the debug package for dbus available to be used by
gdb on x86-64 and allows parallel installation of the development
packages for both x86 and x86-64 architectures.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2010:110");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/24");
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

if (rpm_check(reference:"dbus-1.2.16-3mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"dbus-doc-1.2.16-3mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"dbus-x11-1.2.16-3mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libdbus-1_3-1.2.16-3mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libdbus-1-devel-1.2.16-3mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"dbus-1.2.16-3mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"dbus-doc-1.2.16-3mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"dbus-x11-1.2.16-3mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64dbus-1_3-1.2.16-3mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64dbus-1-devel-1.2.16-3mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;


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
