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
# Mandriva Linux Security Advisory MDVA-2008:070.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(38007);
  script_version ("$Revision: 1.8 $"); 
  script_cvs_date("$Date: 2012/10/04 19:39:04 $");

  script_name(english:"MDVA-2008:070 : dkms");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"The dkms-minimal package in Mandriva Linux 2008 Spring did not
require lsb-release. If lsb-release was not installed, the dkms
modules were installed in the standard location, instead of the
intended /dkms or /dkms-binary. This update fixes that issue.

Due to another bug, dkms would consider older installed binary dkms
modules as original modules when installing a newer version of the
module as a source dkms package, thus wrongly moving the binary
modules around. This update disables original_module handling, not
needed anymore since the rework of dkms system in 2008 Spring.

Dkms would also print an error message during an upgrade of binary
module packages, and under certain conditions an additional warning
message regarding multiple modules being found. This update removes
those harmless messages when they are not appropriate.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2008:070");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/26");
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

if (rpm_check(reference:"dkms-2.0.19-4.3mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"dkms-minimal-2.0.19-4.3mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"dkms-2.0.19-4.3mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"dkms-minimal-2.0.19-4.3mdv2008.1", release:"MDK2008.1", cpu:"noarch", yank:"mdv")) flag++;


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
