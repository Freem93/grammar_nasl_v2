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
# Mandriva Linux Security Advisory MDVA-2008:135-1.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(36787);
  script_version ("$Revision: 1.8 $"); 
  script_cvs_date("$Date: 2012/10/04 19:39:05 $");

  script_name(english:"MDVA-2008:135-1 : draksnapshot");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"This update fixes several issues in draksnapshot:

The draksnapshot applet received the following fixes:

- on desktop startup, it will wait for 30s before checking for
available disc so that notification is positioned at the right place,
on the applet icon - it prevents crashing if DBus is not reachable,
and reports DBus errors - it prevents crashing if DBus is active, but
HAL is not (#44434) - if all discs are unmounted, the applet will
hide (#41176) - it prevents running more than once - it uses HAL in
order to detect discs available for backup, thus fixing detecting
some internal SATA discs as discs available for backup (#41107)

It also uses new icons from Mandriva Linux 2009.0.

The draksnapshot configuration tool also received the following
fixes:

- it stops saving config when clicking Close (#39790); one has to
click on Apply in order to save the config - on first run, it offers
backup in mounted disc path, instead of defaulting to some place in
the root filesystem which could previously be filled up (#39802) - it
no longer offers to configure some obscure advanced options - it now
allows for disabling backups - it generates anacron-friendly cron
files

Update:

An updated draksnapshot is now available for Mandriva Linux 2009.0.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2008:135-1");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/09");
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

if (rpm_check(reference:"draksnapshot-0.19-2mdv2009.0", release:"MDK2009.0", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"draksnapshot-0.19-2mdv2009.0", release:"MDK2009.0", cpu:"noarch", yank:"mdv")) flag++;


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
