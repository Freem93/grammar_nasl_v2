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
# Mandriva Linux Security Advisory MDVA-2008:121.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(36480);
  script_version ("$Revision: 1.8 $"); 
  script_cvs_date("$Date: 2012/10/04 19:39:05 $");

  script_name(english:"MDVA-2008:121 : blt");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"An updated blt package is provided that fixes two issues.

The first is that the package contains two symlinks named
/usr/bin/bltsh and /usr/bin/bltwish that were intended to make it
easier to launch these two utilities. However, they were linked to
files that did not exist, and consequently did not work.

The second is that neither utility will actually run when launched
correctly: they complain that Tcl version 8.5.1 is present, but that
version 8.5 is needed. This over-enthusiastic version check is
dampened by the update, resulting in the utilities both running as
expected.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2008:121");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/11");
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

if (rpm_check(reference:"blt-2.4z-15.2mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"blt-scripts-2.4z-15.2mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libblt2-2.4z-15.2mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libblt2-devel-2.4z-15.2mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"blt-2.4z-15.2mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"blt-scripts-2.4z-15.2mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64blt2-2.4z-15.2mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64blt2-devel-2.4z-15.2mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;


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
