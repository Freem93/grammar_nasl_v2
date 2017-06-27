#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:172. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(61936);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/06/01 00:27:14 $");

  script_cve_id("CVE-2011-2685", "CVE-2011-2713");
  script_bugtraq_id(48387, 49969);
  script_xref(name:"MDVSA", value:"2011:172");

  script_name(english:"Mandriva Linux Security Advisory : libreoffice (MDVSA-2011:172)");
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
"Multiple vulnerabilies has been discovered and corrected in
libreoffice :

Stack-based buffer overflow in the Lotus Word Pro import filter in
LibreOffice before 3.3.3 allows remote attackers to execute arbitrary
code via a crafted .lwp file (CVE-2011-2685).

oowriter in OpenOffice.org 3.3.0 and LibreOffice before 3.4.3 allows
user-assisted remote attackers to cause a denial of service (crash)
via a crafted DOC file that triggers an out-of-bounds read in the DOC
sprm parser (CVE-2011-2713).

This update brings a new LibreOffice version 3.4.3 release linked
against stdc++ and gcc_s standard libraries available in the Mandriva
2011 and solves installing conflicts with libstdc++ (#64224).

The package clipart-openclipart was dropped from the main repository
in the Mandriva 2011. However it is not required having
clipart-openclipart installed in order to install
libreoffice-openclipart as the LibreOffice still provides some
cliparts directly in that package (#63634).

This update fixes some OpenOffice.org leftovers in some packages
description replacing that by LibreOffice (#64658).

This update brings new LibreOffice l10n locale packages: Assanese as,
Bengali bn, Dzongkha dz, Farsi fa, Irish ga, Galician gl, Gujarati gu,
Croatian hr, Kannada kn, Lithuanian lt, Latvian lv, Maithili mai,
Malayalam ml, Marathi mr, Ndebele nr, Northern Shoto nso, Oriya or,
Punjabi pa_IN, Romanian ro, Secwepemctsin sh, Sinhalese si, Serbian
sr, Swati ss, Shoto st, Telugu te, Thai th, Tswana tn, Tsonga ts,
Ukrainian uk, Venda ve and Xhosa xh. Help packages are also provided
for: bn, dz, gl, gu, hr, si and uk.

Additionally the gaupol packages are being provided to solve a build
dependcy of some of the supporting tools already added into 2011.

The updated packages have been upgraded to LibreOffice version 3.4.3
where these isssues has been resolved."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gaupol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64graphite2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64graphite2_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgraphite2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgraphite2_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-devel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-filter-binfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-en_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-en_US");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-help-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-java-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-kde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-en_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-pa_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-sh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-l10n-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-openclipart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-pdfimport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-presentation-minimizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-presenter-screen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-style-crystal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-style-galaxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-style-hicontrast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-style-oxygen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-style-tango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-testtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-wiki-publisher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-aeidon");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2011");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2011", reference:"gaupol-0.18-1.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64graphite2-devel-1.0.3-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64graphite2_2-1.0.3-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libgraphite2-devel-1.0.3-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libgraphite2_2-1.0.3-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-base-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-calc-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-common-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-core-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-devel-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-devel-doc-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-draw-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-filter-binfilter-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-gnome-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-bg-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-bn-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-bs-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-ca-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-cs-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-da-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-de-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-dz-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-el-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-en_GB-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-en_US-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-es-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-et-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-eu-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-fi-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-fr-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-gl-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-gu-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-he-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-hi-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-hr-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-hu-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-it-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-ja-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-ko-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-mk-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-nb-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-nl-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-nn-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-pl-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-pt-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-pt_BR-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-ru-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-si-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-sk-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-sl-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-sv-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-tr-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-uk-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-zh_CN-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-help-zh_TW-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-impress-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-java-common-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-kde4-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-af-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-ar-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-as-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-bg-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-bn-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-br-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-bs-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-ca-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-cs-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-cy-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-da-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-de-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-dz-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-el-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-en_GB-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-es-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-et-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-eu-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-fa-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-fi-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-fr-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-ga-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-gl-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-gu-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-he-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-hi-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-hr-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-hu-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-it-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-ja-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-kn-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-ko-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-lt-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-lv-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-mai-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-mk-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-ml-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-mr-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-nb-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-nl-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-nn-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-nr-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-nso-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-or-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-pa_IN-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-pl-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-pt-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-pt_BR-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-ro-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-ru-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-sh-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-si-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-sk-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-sl-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-sr-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-ss-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-st-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-sv-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-ta-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-te-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-th-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-tn-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-tr-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-ts-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-uk-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-ve-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-xh-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-zh_CN-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-zh_TW-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-l10n-zu-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-math-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-openclipart-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-pdfimport-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-presentation-minimizer-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-presenter-screen-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-pyuno-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-style-crystal-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-style-galaxy-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-style-hicontrast-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-style-oxygen-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-style-tango-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-testtool-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-wiki-publisher-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libreoffice-writer-3.4.3-2.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"python-aeidon-0.18-1.1-mdv2011.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
