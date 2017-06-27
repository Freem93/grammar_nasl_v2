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
# Mandriva Linux Security Advisory MDVA-2011:000.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(51790);
  script_version("$Revision: 1.6 $"); 
  script_cvs_date("$Date: 2012/10/04 19:39:10 $");

  script_name(english:"MDVA-2011:000 : openoffice.org");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"This is a bugfix and maintenance advisory that upgrades
OpenOffice.org to the 3.2.1 version. Additionally a couple of
Mandriva reported bugs has been fixed as described as follows:

Openoffice.org status bar items got hidden whenever using
openoffice.org-kde4 package integration.

Viewing OpenOffice.org documents inside Firefox under 64bits 2010.1
version was not possible.

Additionally OpenOffice.org 3.2.1 requires saxon9 that is also
provided with this advisory.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2011:000");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2011/01/28");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Mandriva Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");

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

if (rpm_check(reference:"openoffice.org-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-base-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-calc-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-common-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-core-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-devel-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-devel-doc-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-draw-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-filter-binfilter-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-gnome-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-af-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-ar-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-bg-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-br-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-bs-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-ca-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-cs-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-cy-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-da-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-de-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-el-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-en_GB-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-en_US-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-es-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-et-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-eu-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-fi-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-fr-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-he-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-hi-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-hu-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-it-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-ja-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-ko-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-mk-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-nb-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-nl-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-nn-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-pl-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-pt-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-pt_AO-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-pt_BR-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-ru-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-sk-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-sl-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-sv-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-ta-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-tr-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-zh_CN-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-zh_TW-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-zu-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-impress-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-java-common-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-kde4-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-af-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-ar-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-bg-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-br-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-bs-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-ca-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-cs-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-cy-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-da-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-de-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-el-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-en_GB-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-es-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-et-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-eu-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-fi-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-fr-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-he-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-hi-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-hu-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-it-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-ja-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-ko-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-mk-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-nb-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-nl-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-nn-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-pl-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-pt-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-pt_AO-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-pt_BR-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-ru-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-sk-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-sl-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-sv-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-ta-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-tr-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-zh_CN-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-zh_TW-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-zu-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-math-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-mono-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-openclipart-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-pdfimport-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-presentation-minimizer-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-presenter-screen-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-pyuno-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-style-crystal-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-style-galaxy-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-style-hicontrast-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-style-industrial-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-style-oxygen-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-style-tango-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-testtool-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-wiki-publisher-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-writer-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"saxon9-9.2.0.3-4.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"saxon9-demo-9.2.0.3-4.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"saxon9-javadoc-9.2.0.3-4.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"saxon9-manual-9.2.0.3-4.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"saxon9-scripts-9.2.0.3-4.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"saxon9-9.2.0.3-4.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"saxon9-demo-9.2.0.3-4.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"saxon9-javadoc-9.2.0.3-4.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"saxon9-manual-9.2.0.3-4.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"saxon9-scripts-9.2.0.3-4.1mdv2010.2", release:"MDK2010.1", cpu:"noarch", yank:"mdv")) flag++;

if (rpm_check(reference:"openoffice.org-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-base-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-calc-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-common-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-core-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-devel-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-devel-doc-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-draw-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-filter-binfilter-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-gnome-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-af-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-ar-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-bg-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-br-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-bs-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-ca-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-cs-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-cy-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-da-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-de-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-el-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-en_GB-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-en_US-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-es-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-et-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-eu-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-fi-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-fr-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-he-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-hi-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-hu-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-it-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-ja-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-ko-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-mk-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-nb-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-nl-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-nn-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-pl-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-pt-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-pt_AO-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-pt_BR-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-ru-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-sk-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-sl-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-sv-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-ta-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-tr-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-zh_CN-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-zh_TW-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-help-zu-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-impress-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-java-common-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-kde4-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-af-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-ar-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-bg-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-br-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-bs-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-ca-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-cs-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-cy-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-da-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-de-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-el-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-en_GB-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-es-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-et-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-eu-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-fi-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-fr-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-he-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-hi-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-hu-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-it-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-ja-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-ko-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-mk-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-nb-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-nl-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-nn-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-pl-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-pt-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-pt_AO-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-pt_BR-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-ru-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-sk-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-sl-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-sv-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-ta-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-tr-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-zh_CN-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-zh_TW-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-l10n-zu-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-math-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-mono-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-openclipart-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-pdfimport-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-presentation-minimizer-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-presenter-screen-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-pyuno-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-style-crystal-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-style-galaxy-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-style-hicontrast-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-style-industrial-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-style-oxygen-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-style-tango-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-testtool-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-wiki-publisher-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"openoffice.org-writer-3.2.1-0.2mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;


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
