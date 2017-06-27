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
# Mandrake Linux Security Advisory MDKA-2007:041.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(25264);
  script_version ("$Revision: 1.9 $"); 
  script_cvs_date("$Date: 2012/09/07 00:24:00 $");

  script_name(english:"MDKA-2007:041 : console-tools");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandrake host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"A limitation on the setkeycodes utility in the console-tools package
was found, where it wasn't possible to set a keycode greater than
128, making it impossible to use extra keys like multimedia keys on
Logitech keyboards or extra keys on many laptops.

The updated packages raise the limit of keycodes allowed, up to 240.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDKA-2007:041");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/18");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/05/20");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Mandriva Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");

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

if (rpm_check(reference:"console-tools-0.2.3-60.1mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libconsole0-0.2.3-60.1mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libconsole0-devel-0.2.3-60.1mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libconsole0-static-devel-0.2.3-60.1mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"console-tools-0.2.3-60.1mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64console0-0.2.3-60.1mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64console0-devel-0.2.3-60.1mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64console0-static-devel-0.2.3-60.1mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;

if (rpm_check(reference:"console-tools-0.2.3-61.1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libconsole0-0.2.3-61.1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libconsole0-devel-0.2.3-61.1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libconsole0-static-devel-0.2.3-61.1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"console-tools-0.2.3-61.1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64console0-0.2.3-61.1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64console0-devel-0.2.3-61.1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64console0-static-devel-0.2.3-61.1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;


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
