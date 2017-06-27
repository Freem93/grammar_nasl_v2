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
# Mandriva Linux Security Advisory MDVA-2008:027.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(36483);
  script_version ("$Revision: 1.8 $"); 
  script_cvs_date("$Date: 2012/10/04 19:39:04 $");

  script_name(english:"MDVA-2008:027 : mandriva-kde-config");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"The KDE panel has a clock applet which includes de hability to change
its appearance and behavior. Because of a configuration problem, this
applet was not properly saving these changes were not properly saved,
being lost at every user login.

This update fixes the problem.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2008:027");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/13");
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

if (rpm_check(reference:"free-kde-config-2008.0-29.1mdv2008.0", release:"MDK2008.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-kde-config-common-2008.0-29.1mdv2008.0", release:"MDK2008.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-kdm-config-2008.0-29.1mdv2008.0", release:"MDK2008.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"one-kde-config-2008.0-29.1mdv2008.0", release:"MDK2008.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"powerpack-kde-config-2008.0-29.1mdv2008.0", release:"MDK2008.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"free-kde-config-2008.0-29.1mdv2008.0", release:"MDK2008.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-kde-config-common-2008.0-29.1mdv2008.0", release:"MDK2008.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-kdm-config-2008.0-29.1mdv2008.0", release:"MDK2008.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"one-kde-config-2008.0-29.1mdv2008.0", release:"MDK2008.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"powerpack-kde-config-2008.0-29.1mdv2008.0", release:"MDK2008.0", cpu:"noarch", yank:"mdv")) flag++;


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
