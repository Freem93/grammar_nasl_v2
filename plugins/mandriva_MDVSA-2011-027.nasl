#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:027. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(51982);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/09/02 15:06:43 $");

  script_cve_id("CVE-2010-3450", "CVE-2010-3451", "CVE-2010-3452", "CVE-2010-3453", "CVE-2010-3454", "CVE-2010-3689", "CVE-2010-4253", "CVE-2010-4643");
  script_bugtraq_id(46031);
  script_xref(name:"MDVSA", value:"2011:027");

  script_name(english:"Mandriva Linux Security Advisory : openoffice.org (MDVSA-2011:027)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered and corrected in
OpenOffice.org :

Multiple directory traversal vulnerabilities allow remote attackers to
overwrite arbitrary files via a .. (dot dot) in an entry in an XSLT
JAR filter description file, an Extension (aka OXT) file, or
unspecified other JAR or ZIP files (CVE-2010-3450).

Use-after-free vulnerability in oowriter allows remote attackers to
cause a denial of service (application crash) or possibly execute
arbitrary code via malformed tables in an RTF document
(CVE-2010-3451).

Use-after-free vulnerability in oowriter allows remote attackers to
cause a denial of service (application crash) or possibly execute
arbitrary code via crafted tags in an RTF document (CVE-2010-3452).

The WW8ListManager::WW8ListManager function in oowriter does not
properly handle an unspecified number of list levels in user-defined
list styles in WW8 data in a Microsoft Word document, which allows
remote attackers to cause a denial of service (application crash) or
possibly execute arbitrary code via a crafted .DOC file that triggers
an out-of-bounds write (CVE-2010-3453).

Multiple off-by-one errors in the WW8DopTypography::ReadFromMem
function in oowriter allow remote attackers to cause a denial of
service (application crash) or possibly execute arbitrary code via
crafted typography information in a Microsoft Word .DOC file that
triggers an out-of-bounds write (CVE-2010-3454).

soffice places a zero-length directory name in the LD_LIBRARY_PATH,
which allows local users to gain privileges via a Trojan horse shared
library in the current working directory (CVE-2010-3689).

Heap-based buffer overflow in Impress allows remote attackers to cause
a denial of service (application crash) or possibly execute arbitrary
code via a crafted PNG file in an ODF or Microsoft Office document, as
demonstrated by a PowerPoint (aka PPT) document (CVE-2010-4253).

Heap-based buffer overflow in Impress allows remote attackers to cause
a denial of service (application crash) or possibly execute arbitrary
code via a crafted TGA file in an ODF or Microsoft Office document
(CVE-2010-4643).

OpenOffice.org packages have been updated in order to fix these
issues. Additionally openoffice.org-voikko packages that require
OpenOffice.org are also being provided and voikko package is upgraded
from 2.0 to 2.2.1 version in MES5.1."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-devel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-filter-binfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-en_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-en_US");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-pt_AO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-help-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-java-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-kde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-en_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-pt_AO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-openclipart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-pdfimport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-presentation-minimizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-presenter-screen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-style-crystal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-style-galaxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-style-hicontrast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-style-industrial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-style-oxygen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-style-tango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-testtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-voikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-wiki-publisher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-writer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-base-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-calc-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-common-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-core-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-devel-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-devel-doc-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-draw-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-filter-binfilter-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-gnome-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-af-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-ar-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-bg-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-br-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-bs-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-ca-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-cs-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-cy-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-da-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-de-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-el-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-en_GB-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-en_US-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-es-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-et-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-eu-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-fi-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-fr-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-he-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-hi-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-hu-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-it-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-ja-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-ko-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-mk-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-nb-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-nl-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-nn-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-pl-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-pt-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-pt_BR-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-ru-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-sk-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-sl-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-sv-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-ta-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-tr-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-zh_CN-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-zh_TW-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-help-zu-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-impress-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-java-common-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-af-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-ar-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-bg-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-br-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-bs-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-ca-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-cs-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-cy-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-da-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-de-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-el-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-en_GB-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-es-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-et-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-eu-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-fi-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-fr-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-he-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-hi-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-hu-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-it-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-ja-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-ko-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-mk-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-nb-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-nl-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-nn-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-pl-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-pt-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-pt_BR-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-ru-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-sk-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-sl-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-sv-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-ta-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-tr-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-zh_CN-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-zh_TW-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-l10n-zu-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-math-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-mono-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-openclipart-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-pdfimport-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-presentation-minimizer-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-presenter-screen-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-pyuno-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-style-crystal-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-style-galaxy-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-style-hicontrast-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-style-industrial-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-style-tango-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-testtool-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-voikko-3.1-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-wiki-publisher-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"openoffice.org-writer-3.1.1-0.8mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-base-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-calc-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-common-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-core-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-devel-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-devel-doc-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-draw-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-filter-binfilter-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-gnome-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-af-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-ar-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-bg-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-br-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-bs-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-ca-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-cs-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-cy-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-da-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-de-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-el-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-en_GB-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-en_US-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-es-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-et-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-eu-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-fi-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-fr-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-he-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-hi-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-hu-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-it-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-ja-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-ko-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-mk-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-nb-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-nl-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-nn-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-pl-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-pt-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-pt_BR-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-ru-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-sk-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-sl-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-sv-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-ta-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-tr-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-zh_CN-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-zh_TW-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-help-zu-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-impress-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-java-common-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-af-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-ar-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-bg-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-br-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-bs-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-ca-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-cs-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-cy-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-da-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-de-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-el-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-en_GB-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-es-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-et-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-eu-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-fi-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-fr-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-he-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-hi-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-hu-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-it-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-ja-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-ko-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-mk-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-nb-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-nl-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-nn-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-pl-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-pt-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-pt_BR-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-ru-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-sk-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-sl-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-sv-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-ta-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-tr-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-zh_CN-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-zh_TW-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-l10n-zu-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-math-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-mono-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-openclipart-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-pdfimport-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-presentation-minimizer-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-presenter-screen-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-pyuno-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-style-crystal-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-style-galaxy-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-style-hicontrast-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-style-industrial-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-style-tango-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-testtool-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-voikko-3.1-3.3mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-wiki-publisher-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"openoffice.org-writer-3.1.1-2.7mdv2010.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-base-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-calc-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-common-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-core-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-devel-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-devel-doc-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-draw-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-filter-binfilter-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-gnome-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-af-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-ar-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-bg-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-br-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-bs-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-ca-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-cs-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-cy-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-da-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-de-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-el-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-en_GB-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-en_US-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-es-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-et-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-eu-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-fi-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-fr-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-he-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-hi-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-hu-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-it-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-ja-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-ko-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-mk-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-nb-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-nl-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-nn-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-pl-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-pt-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-pt_AO-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-pt_BR-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-ru-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-sk-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-sl-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-sv-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-ta-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-tr-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-zh_CN-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-zh_TW-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-help-zu-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-impress-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-java-common-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-kde4-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-af-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-ar-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-bg-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-br-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-bs-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-ca-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-cs-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-cy-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-da-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-de-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-el-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-en_GB-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-es-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-et-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-eu-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-fi-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-fr-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-he-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-hi-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-hu-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-it-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-ja-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-ko-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-mk-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-nb-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-nl-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-nn-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-pl-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-pt-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-pt_AO-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-pt_BR-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-ru-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-sk-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-sl-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-sv-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-ta-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-tr-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-zh_CN-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-zh_TW-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-l10n-zu-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-math-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-mono-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-openclipart-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-pdfimport-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-presentation-minimizer-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-presenter-screen-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-pyuno-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-style-crystal-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-style-galaxy-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-style-hicontrast-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-style-industrial-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-style-oxygen-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-style-tango-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-testtool-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-voikko-3.1-4.4mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-wiki-publisher-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"openoffice.org-writer-3.2.1-0.3mdv2010.2", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
