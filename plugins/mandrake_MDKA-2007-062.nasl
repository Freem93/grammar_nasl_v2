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
# Mandrake Linux Security Advisory MDKA-2007:062.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(36892);
  script_version ("$Revision: 1.7 $"); 
  script_cvs_date("$Date: 2012/09/07 00:24:00 $");

  script_name(english:"MDKA-2007:062 : rpmdrake");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandrake host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"The rpmdrake package, which provides the graphical software
installation and update tools rpmdrake, drakrpm-edit-media and
MandrivaUpdate), included with Mandriva Linux 2007 Spring contains
several bugs. These include:

When installing software with rpmdrake, if packages are selected for
installation which require other packages to be installed as well, a
message will be displayed that says To satisfy dependencies, the
following packages also need to be installed:, but no list of
dependencies will actually be shown.

When installing software with rpmdrake, searching for a package
always searches through the full set of available packages even when
a search filter - such as All updates or Mandriva choices - is
selected.

When installing software with rpmdrake, when you switch between two
subsections with the same name - for instance, System/Settings/Other
and Development/Other - the list of packages is not updated; in the
example, the packages from the System/Settings/Other group will
continue to be displayed, instead of the packages from
Development/Other.

Running rpmdrake with the --merge-all-rpmnew parameter, which uses
rpmdrake to help you merge changes in updated configuration files,
does not work.

When updating your system with MandrivaUpdate, when a package name
cannot be correctly parsed, the name of the previous package in the
list will be displayed again instead.

When installing software with rpmdrake, the application will crash if
a package with a malformed summary in the Unicode text encoding
system was selected.

Some other, more minor bugs were also fixed in this update.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDKA-2007:062");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/20");
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

if (rpm_check(reference:"park-rpmdrake-3.68-1.1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"rpmdrake-3.68-1.1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"park-rpmdrake-3.68-1.1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"rpmdrake-3.68-1.1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;


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
