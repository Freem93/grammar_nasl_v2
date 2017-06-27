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
# Mandriva Linux Security Advisory MDVA-2008:162.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(37221);
  script_version ("$Revision: 1.8 $"); 
  script_cvs_date("$Date: 2012/10/04 19:39:05 $");

  script_name(english:"MDVA-2008:162 : openoffice.org");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"This update provides a new upstream version of OpenOffice.org -
2.4.1.10. It also corrects the following bugs:

Under 2.4 versions of OpenOffice.org, the Orientation option was
removed from printer properties which prevented users from printing
on a booklet format in a way they were used to do. This
OpenOffice.org update enables the Orientation printer option again.

Another problem was on OpenOffice.org application start up which was
hanging when LDAP authentication is enabled on x86_64 machines.
OpenOffice.org tried to access info about logged on user name but it
did not provide the right parameters to the libnss_ldap library. As a
work around, we have forced the installation of the i586 package of
that library. This update stops OpenOffice.org from obtaining running
user information on LDAP authentication since it does not block
sensible working features.

Another bug fixed in this update is the handling of text and numbers
on cells that are aligned on a different position degree as usual,
such as 90 degrees. This caused information on that cell being showed
in such a way that numbers got a different degree than alphabetic
characters.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2008:162");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/30");
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

if (rpm_check(reference:"openoffice.org-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-base-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-calc-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-common-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-core-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-devel-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-devel-doc-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-draw-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-dtd-officedocument1.0-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-filter-binfilter-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-gnome-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-af-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-ar-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-bg-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-br-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-bs-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-ca-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-cs-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-cy-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-da-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-de-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-el-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-en_GB-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-es-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-et-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-eu-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-fi-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-fr-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-he-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-hi-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-hu-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-it-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-ja-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-ko-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-mk-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-nb-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-nl-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-nn-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-pl-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-pt-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-pt_BR-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-ru-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-sk-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-sl-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-sv-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-ta-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-tr-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-zh_CN-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-zh_TW-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-zu-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-impress-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-java-common-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-kde-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-af-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-ar-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-bg-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-br-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-bs-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-ca-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-cs-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-cy-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-da-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-de-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-el-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-en_GB-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-es-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-et-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-eu-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-fi-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-fr-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-he-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-hi-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-hu-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-it-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-ja-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-ko-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-mk-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-nb-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-nl-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-nn-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-pl-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-pt-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-pt_BR-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-ru-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-sk-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-sl-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-sv-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-ta-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-tr-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-zh_CN-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-zh_TW-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-zu-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-math-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-mono-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-openclipart-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-pyuno-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-style-andromeda-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-style-crystal-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-style-hicontrast-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-style-industrial-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-style-tango-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-testtool-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-voikko-2.2-4.5mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-voikko-debug-2.2-4.5mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-writer-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"openoffice.org64-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-base-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-calc-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-common-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-core-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-devel-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-devel-doc-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-draw-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-dtd-officedocument1.0-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-filter-binfilter-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-gnome-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-af-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-ar-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-bg-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-br-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-bs-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-ca-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-cs-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-cy-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-da-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-de-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-el-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-en_GB-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-es-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-et-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-eu-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-fi-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-fr-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-he-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-hi-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-hu-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-it-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-ja-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-ko-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-mk-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-nb-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-nl-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-nn-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-pl-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-pt-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-pt_BR-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-ru-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-sk-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-sl-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-sv-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-ta-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-tr-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-zh_CN-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-zh_TW-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-help-zu-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-impress-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-java-common-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-kde-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-af-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-ar-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-bg-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-br-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-bs-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-ca-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-cs-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-cy-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-da-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-de-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-el-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-en_GB-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-es-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-et-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-eu-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-fi-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-fr-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-he-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-hi-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-hu-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-it-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-ja-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-ko-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-mk-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-nb-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-nl-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-nn-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-pl-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-pt-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-pt_BR-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-ru-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-sk-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-sl-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-sv-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-ta-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-tr-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-zh_CN-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-zh_TW-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-l10n-zu-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-math-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-mono-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-openclipart-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-pyuno-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-style-andromeda-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-style-crystal-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-style-hicontrast-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-style-industrial-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-style-tango-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-testtool-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-voikko-2.2-4.5mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org64-writer-2.4.1.10-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-voikko-debug-2.2-4.5mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;


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
