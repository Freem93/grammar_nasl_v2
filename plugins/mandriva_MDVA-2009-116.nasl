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
# Mandriva Linux Security Advisory MDVA-2009:116.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(39460);
  script_version ("$Revision: 1.8 $"); 
  script_cvs_date("$Date: 2012/10/04 19:39:07 $");

  script_name(english:"MDVA-2009:116 : glibc");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"New glibc release to fix some issues found in glibc 2.8 present in
Mandriva 2009.0:

- ulimit(UL_SETFSIZE) does not return the integer part of the new
file size limit divided by 512
(http://linuxtesting.org/results/report?num=S0167, Mandriva bug
#51685)

- When including pthread.h and using pthread_cleanup_pop or
pthread_cleanup_pop_restore_np macros, a compiler warning is issued
or build error happens if -Werror is used
(http://sourceware.org/bugzilla/show_bug.cgi?id=7056, Mandriva bug
#49142)");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2009:116");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/18");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/06/19");
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

if (rpm_check(reference:"glibc-2.8-1.20080520.5.4mnb2", release:"MDK2009.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-devel-2.8-1.20080520.5.4mnb2", release:"MDK2009.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-doc-2.8-1.20080520.5.4mnb2", release:"MDK2009.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-doc-pdf-2.8-1.20080520.5.4mnb2", release:"MDK2009.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-i18ndata-2.8-1.20080520.5.4mnb2", release:"MDK2009.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-profile-2.8-1.20080520.5.4mnb2", release:"MDK2009.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-static-devel-2.8-1.20080520.5.4mnb2", release:"MDK2009.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-utils-2.8-1.20080520.5.4mnb2", release:"MDK2009.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"nscd-2.8-1.20080520.5.4mnb2", release:"MDK2009.0", cpu:"i386", yank:"mdk")) flag++;

if (rpm_check(reference:"glibc-2.8-1.20080520.5.4mnb2", release:"MDK2009.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-devel-2.8-1.20080520.5.4mnb2", release:"MDK2009.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-doc-2.8-1.20080520.5.4mnb2", release:"MDK2009.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-doc-pdf-2.8-1.20080520.5.4mnb2", release:"MDK2009.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-i18ndata-2.8-1.20080520.5.4mnb2", release:"MDK2009.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-profile-2.8-1.20080520.5.4mnb2", release:"MDK2009.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-static-devel-2.8-1.20080520.5.4mnb2", release:"MDK2009.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"glibc-utils-2.8-1.20080520.5.4mnb2", release:"MDK2009.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"nscd-2.8-1.20080520.5.4mnb2", release:"MDK2009.0", cpu:"x86_64", yank:"mdk")) flag++;


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
