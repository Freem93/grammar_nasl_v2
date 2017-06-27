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
# Mandriva Linux Security Advisory MDVA-2010:134.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(48108);
  script_version("$Revision: 1.6 $"); 
  script_cvs_date("$Date: 2012/10/04 19:39:09 $");

  script_name(english:"MDVA-2010:134 : sane");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"Sane wasn't compiled with V4L (video4linux) support. This packages
update fixes this issue.

Additional packages is being provided to satisfy the added
dependencies.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2010:134");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/26");
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

if (rpm_check(reference:"libsane1-1.0.20-8.1mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libsane1-devel-1.0.20-8.1mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libv4l0-0.6.1-1.1mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libv4l-0.6.1-1.1mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libv4l-devel-0.6.1-1.1mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libv4l-wrappers-0.6.1-1.1mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"sane-backends-1.0.20-8.1mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"sane-backends-doc-1.0.20-8.1mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"sane-backends-iscan-1.0.20-8.1mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"saned-1.0.20-8.1mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"lib64sane1-1.0.20-8.1mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64sane1-devel-1.0.20-8.1mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64v4l0-0.6.1-1.1mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64v4l-devel-0.6.1-1.1mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64v4l-wrappers-0.6.1-1.1mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"libv4l-0.6.1-1.1mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"sane-backends-1.0.20-8.1mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"sane-backends-doc-1.0.20-8.1mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"sane-backends-iscan-1.0.20-8.1mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"saned-1.0.20-8.1mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;


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
