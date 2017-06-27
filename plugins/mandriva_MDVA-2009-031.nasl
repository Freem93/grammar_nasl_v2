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
# Mandriva Linux Security Advisory MDVA-2009:031.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(36715);
  script_version ("$Revision: 1.8 $"); 
  script_cvs_date("$Date: 2012/10/04 19:39:06 $");

  script_name(english:"MDVA-2009:031 : drakx-net");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"This update several minor issues with Mandriva Network tools
(drakx-net).

- drakroam would crash if no wireless interface is present on the
system.

- Cancel button of Interactive Firewall configuration screen of
drakfirewall was not handled correctly (bug #46256)

- Interactive Firewall settings were not applied immediately after
changing firewall configuration (bug #47370)

- Unicode dates were not displayed correctly in drakids (bug #39914)

- Network interface name was not displayed in drakconnect, leading to
confusion when several identical cards are present in the system (bug
#45881)

- When guessing DNS and GW addresses for static address connections,
the guessed IPs were different (bug #7041)

- Network monitor would display negative traffic amount when
transferring over 4GB of data (bug #46398)

- Custom MTU values were not preserved when changing network
configuration using drakconnect (bug #45969)

- The excessive number of failed connection attempts to ADSL networks
could lead to extremely long boot times (bug #28087).");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2009:031");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/26");
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

if (rpm_check(reference:"drakx-net-0.54.4-1.1mdv2009.0", release:"MDK2009.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"drakx-net-text-0.54.4-1.1mdv2009.0", release:"MDK2009.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"libdrakx-net-0.54.4-1.1mdv2009.0", release:"MDK2009.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"drakx-net-0.54.4-1.1mdv2009.0", release:"MDK2009.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"drakx-net-text-0.54.4-1.1mdv2009.0", release:"MDK2009.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"libdrakx-net-0.54.4-1.1mdv2009.0", release:"MDK2009.0", cpu:"noarch", yank:"mdv")) flag++;


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
