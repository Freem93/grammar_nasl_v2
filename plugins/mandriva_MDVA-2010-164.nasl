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
# Mandriva Linux Security Advisory MDVA-2010:164.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(46854);
  script_version("$Revision: 1.7 $"); 
  script_cvs_date("$Date: 2012/10/04 19:39:10 $");

  script_name(english:"MDVA-2010:164 : pidgin");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"Changes on the ICQ servers made the login impossible if the
clientLogin and SSL options were enabled. This update adds patches to
restore these options. Also add xdg patch from cooker.

Packages for 2008.0 and 2009.0 are provided as of the Extended
Maintenance Program. Please visit this link to learn more:
http://store.mandriva.com/product_info.php?cPath=149&products_id=490");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2010:164");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/09");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/06/10");
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

if (rpm_check(reference:"finch-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libfinch0-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libpurple0-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libpurple-devel-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-bonjour-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-client-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-gevolution-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-i18n-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-meanwhile-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-mono-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-perl-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-plugins-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-silc-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-tcl-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"finch-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64finch0-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64purple0-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64purple-devel-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-bonjour-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-client-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-gevolution-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-i18n-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-meanwhile-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-mono-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-perl-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-plugins-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-silc-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-tcl-2.6.6-0.3mdv2008.0", release:"MDK2008.0", cpu:"x86_64", yank:"mdv")) flag++;

if (rpm_check(reference:"finch-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libfinch0-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libpurple0-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libpurple-devel-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-bonjour-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-client-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-gevolution-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-i18n-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-meanwhile-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-mono-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-perl-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-plugins-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-silc-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-tcl-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"finch-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64finch0-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64purple0-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64purple-devel-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-bonjour-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-client-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-gevolution-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-i18n-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-meanwhile-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-mono-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-perl-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-plugins-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-silc-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-tcl-2.6.6-0.3mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;

if (rpm_check(reference:"finch-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libfinch0-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libpurple0-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libpurple-devel-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-bonjour-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-client-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-gevolution-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-i18n-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-meanwhile-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-mono-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-perl-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-plugins-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-silc-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-tcl-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"finch-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64finch0-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64purple0-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64purple-devel-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-bonjour-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-client-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-gevolution-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-i18n-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-meanwhile-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-mono-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-perl-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-plugins-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-silc-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-tcl-2.6.6-0.3mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;

if (rpm_check(reference:"finch-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libfinch0-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libpurple0-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libpurple-devel-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-bonjour-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-client-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-gevolution-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-i18n-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-meanwhile-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-mono-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-perl-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-plugins-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-silc-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-tcl-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"finch-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64finch0-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64purple0-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64purple-devel-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-bonjour-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-client-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-gevolution-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-i18n-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-meanwhile-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-mono-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-perl-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-plugins-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-silc-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pidgin-tcl-2.6.6-0.6mdv2010.0", release:"MDK2010.0", cpu:"x86_64", yank:"mdv")) flag++;


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
