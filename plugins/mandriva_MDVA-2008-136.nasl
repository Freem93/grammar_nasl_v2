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
# Mandriva Linux Security Advisory MDVA-2008:136.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(37286);
  script_version ("$Revision: 1.8 $"); 
  script_cvs_date("$Date: 2012/10/04 19:39:05 $");

  script_name(english:"MDVA-2008:136 : urpmi");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"These updated packages add support for notification of new
distribution releases and allow users to easily upgrade Mandriva
Linux 2008.1 to future Mandriva Linux releases online.

To disable new distribution release notification on a system-wide
basis, change the DO_NOT_ASK_FOR_DISTRO_UPGRADE to 'true' in
/etc/sysconfig/mdkapplet.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2008:136");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/08");
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

if (rpm_check(reference:"gurpmi-5.19.5-1.1mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mdkonline-2.52.2-1.1mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-5.19.5-1.1mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-ldap-5.19.5-1.1mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-parallel-ka-run-5.19.5-1.1mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-parallel-ssh-5.19.5-1.1mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-recover-5.19.5-1.1mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"gurpmi-5.19.5-1.1mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mdkonline-2.52.2-1.1mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-5.19.5-1.1mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-ldap-5.19.5-1.1mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-parallel-ka-run-5.19.5-1.1mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-parallel-ssh-5.19.5-1.1mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-recover-5.19.5-1.1mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;


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
