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
# Mandrake Linux Security Advisory MDKA-2005:057.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(24483);
  script_version ("$Revision: 1.9 $"); 
  script_cvs_date("$Date: 2012/09/07 00:23:59 $");

  script_name(english:"MDKA-2005:057 : drakxtools");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandrake host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"A number of bugs have been fixed in this new drakxtools package,
primarily within the diskdrake, drakconnect and drakroam programs:

Diskdrake fixes include:

- handle 'users' the way 'user' is handled - handle dmraid-1.0.0 RC9
(#19654)

Drakconnect fixes include:

- don't screw up eagle-usb devices if the firmware is already loaded
- fix zd1201 devices detection as well

Drakroam fixes include:

- remember 'restricted' wireless mode - don't crash if mandi isn't
started (#19608) - fix wireless network list using iwlist (#19742)");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDKA-2005:057");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/18");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Mandriva Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");

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

if (rpm_check(reference:"drakx-finish-install-10.3-0.64.3.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"drakxtools-10.3-0.64.3.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"drakxtools-backend-10.3-0.64.3.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"drakxtools-http-10.3-0.64.3.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"drakxtools-newt-10.3-0.64.3.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"harddrake-10.3-0.64.3.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"harddrake-ui-10.3-0.64.3.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;


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
