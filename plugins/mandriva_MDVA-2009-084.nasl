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
# Mandriva Linux Security Advisory MDVA-2009:084.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(47921);
  script_version("$Revision: 1.6 $"); 
  script_cvs_date("$Date: 2012/10/04 19:39:07 $");

  script_name(english:"MDVA-2009:084 : x11-driver-video-intel");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"The intel graphics driver shipped in 2009.1 was the 2.7.0 version
which has turned out to be somewhat unstable on some systems (this
was still more stable overall than earlier versions, but hardly any
consolation to those having problems!).

This updates the package to the 2.7.1 version recently released by
intel and fixes several crashers. The number of changes is quite
small, so hopefully minimises any chances of unexpected regressions.

Here follows the advisory text from the upstream Intel maintainers:


This is a maintenance release on the 2.7 branch. Compared to 2.7.0 it
consists only of a few carefully hand-picked fixes for bugs,
(including GPU crashers). We encourage all users of 2.7.0 to upgrade
to 2.7.1.

We have verified that several of the reported bugs of GPU crashes,
(mouse continues to move, but otherwise X is totally unresponsive),
are fixed with the commit by Keith Packard in 2.7.1 to correct the
computation of the batch space required. If you have previously
reported a GPU-crash bug in bugs.freedesktop.org, please test with
2.7.1 and report your findings in the bug. If the crash is fixed,
please celebrate with us!

If the crash persists, please attach the output of intel_gpu_dump
available here (and hopefully packaged in your distribution of choice
soon)


Please note that the intel_gpu_dump utility refered to above is now
available for 2009.1 via contrib/updates in the intel-gpu-tools
pacakge.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2009:084");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/27");
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

if (rpm_check(reference:"x11-driver-video-intel-2.7.1-0.1mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"x11-driver-video-intel-fast-i830-2.7.1-0.1mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"x11-driver-video-intel-2.7.1-0.1mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"x11-driver-video-intel-fast-i830-2.7.1-0.1mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;


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
