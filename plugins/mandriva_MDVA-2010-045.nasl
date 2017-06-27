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
# Mandriva Linux Security Advisory MDVA-2010:045.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(44325);
  script_version("$Revision: 1.8 $"); 
  script_cvs_date("$Date: 2012/10/04 19:39:09 $");

  script_name(english:"MDVA-2010:045 : urpmi");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"There was a small typo in the french translation. The update packages
addresses this issue.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2010:045");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/27");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/01/28");
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

if (rpm_check(reference:"gurpmi-4.10.14.2-1.2mdv2008.0", release:"MDK2008.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-4.10.14.2-1.2mdv2008.0", release:"MDK2008.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-ldap-4.10.14.2-1.2mdv2008.0", release:"MDK2008.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-parallel-ka-run-4.10.14.2-1.2mdv2008.0", release:"MDK2008.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-parallel-ssh-4.10.14.2-1.2mdv2008.0", release:"MDK2008.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-recover-4.10.14.2-1.2mdv2008.0", release:"MDK2008.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"gurpmi-4.10.14.2-1.2mdv2008.0", release:"MDK2008.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-4.10.14.2-1.2mdv2008.0", release:"MDK2008.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-ldap-4.10.14.2-1.2mdv2008.0", release:"MDK2008.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-parallel-ka-run-4.10.14.2-1.2mdv2008.0", release:"MDK2008.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-parallel-ssh-4.10.14.2-1.2mdv2008.0", release:"MDK2008.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-recover-4.10.14.2-1.2mdv2008.0", release:"MDK2008.0", cpu:"noarch", yank:"mdv")) flag++;

if (rpm_check(reference:"gurpmi-6.14.15-1.3mdv2009.0", release:"MDK2009.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-6.14.15-1.3mdv2009.0", release:"MDK2009.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-ldap-6.14.15-1.3mdv2009.0", release:"MDK2009.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-parallel-ka-run-6.14.15-1.3mdv2009.0", release:"MDK2009.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-parallel-ssh-6.14.15-1.3mdv2009.0", release:"MDK2009.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-recover-6.14.15-1.3mdv2009.0", release:"MDK2009.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"gurpmi-6.14.15-1.3mdv2009.0", release:"MDK2009.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-6.14.15-1.3mdv2009.0", release:"MDK2009.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-ldap-6.14.15-1.3mdv2009.0", release:"MDK2009.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-parallel-ka-run-6.14.15-1.3mdv2009.0", release:"MDK2009.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-parallel-ssh-6.14.15-1.3mdv2009.0", release:"MDK2009.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-recover-6.14.15-1.3mdv2009.0", release:"MDK2009.0", cpu:"noarch", yank:"mdv")) flag++;

if (rpm_check(reference:"gurpmi-6.25.6-1.2mdv2009.1", release:"MDK2009.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-6.25.6-1.2mdv2009.1", release:"MDK2009.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-ldap-6.25.6-1.2mdv2009.1", release:"MDK2009.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-parallel-ka-run-6.25.6-1.2mdv2009.1", release:"MDK2009.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-parallel-ssh-6.25.6-1.2mdv2009.1", release:"MDK2009.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"gurpmi-6.25.6-1.2mdv2009.1", release:"MDK2009.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-6.25.6-1.2mdv2009.1", release:"MDK2009.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-ldap-6.25.6-1.2mdv2009.1", release:"MDK2009.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-parallel-ka-run-6.25.6-1.2mdv2009.1", release:"MDK2009.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"urpmi-parallel-ssh-6.25.6-1.2mdv2009.1", release:"MDK2009.1", cpu:"noarch", yank:"mdv")) flag++;


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
