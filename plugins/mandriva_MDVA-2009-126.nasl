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
# Mandriva Linux Security Advisory MDVA-2009:126.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(47940);
  script_version("$Revision: 1.6 $"); 
  script_cvs_date("$Date: 2012/10/04 19:39:07 $");

  script_name(english:"MDVA-2009:126 : initscripts");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"This package update fixes several issues when using speedboot mode in
conjunction with failsafe mode, crypted filesystem, network profiles.
It also improves readahead behaviour and reduce startup boot time.
System installed from One edition will now have speedboot enabled.

Bugs fixed : - Only enable CRDA domain if wireless cards are present
(Mdv bug #51795) - readahead calls are now blocking and done earlier,
for better performance (Mdv bug #44471) - disable speedboot if
netprofiles are detected and not selected in kernel cmdline (Mdv bug
#51550) - disable speedboot at each boot when /etc/crypttab is
detected (Mdv bug #51518) - Fix speedboot status staying at STANDARD
BOOT (Mdv bug #50238) - disable speedboot in failsafe mode (Mdv bug
#51706) - disable speedboot only when LVM / RAID volumes are detected
(Mdv bug #50270) - installing quota no longer disables speedboot (Mdv
bug #50270) - hide error when readahead_later list isn't available
(Mdv bug #51365)");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2009:126");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/04");
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

if (rpm_check(reference:"debugmode-8.88-23.1mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"initscripts-8.88-23.1mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"readahead-1.4.9-3.1mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"debugmode-8.88-23.1mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"initscripts-8.88-23.1mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"readahead-1.4.9-3.1mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;


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
