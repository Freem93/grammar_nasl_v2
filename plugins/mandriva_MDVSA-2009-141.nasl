#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:141. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(39581);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/28 21:39:23 $");

  script_cve_id("CVE-2009-1302", "CVE-2009-1303", "CVE-2009-1304", "CVE-2009-1305", "CVE-2009-1306", "CVE-2009-1307", "CVE-2009-1308", "CVE-2009-1309", "CVE-2009-1392", "CVE-2009-1832", "CVE-2009-1833", "CVE-2009-1836", "CVE-2009-1838", "CVE-2009-1840", "CVE-2009-1841", "CVE-2009-2210");
  script_bugtraq_id(35370, 35371, 35372, 35373, 35377, 35380, 35383);
  script_xref(name:"MDVSA", value:"2009:141");

  script_name(english:"Mandriva Linux Security Advisory : mozilla-thunderbird (MDVSA-2009:141)");
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
"A number of security vulnerabilities have been discovered for Mozilla
Thunderbird version 2.0.0.21 (CVE-2009-1302, CVE-2009-1303,
CVE-2009-1304, CVE-2009-1305, CVE-2009-1306, CVE-2009-1307,
CVE-2009-1308, CVE-2009-1309, CVE-2009-2210, CVE-2009-1392,
CVE-2009-1832, CVE-2009-1833, CVE-2009-1838, CVE-2009-1836,
CVE-2009-1840, CVE-2009-1841).

This update provides the latest Thunderbird to correct these issues."
  );
  # http://www.mozilla.org/security/known-vulnerabilities/thunderbird20.html#thunderbird2.0.0.21
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9ed122c0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(16, 20, 79, 94, 264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:beagle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:beagle-crawl-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:beagle-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:beagle-epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:beagle-evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:beagle-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:beagle-gui-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:beagle-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:firefox-ext-beagle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-beagle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-en_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-es_AR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-es_AR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-es_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-et_EE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-gu_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-moztraybiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-nb_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-nn_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-pa_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-pt_PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-sv_SE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nsinstall");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2009.0", reference:"beagle-0.3.8-13.12mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"beagle-crawl-system-0.3.8-13.12mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"beagle-doc-0.3.8-13.12mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"beagle-epiphany-0.3.8-13.12mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"beagle-evolution-0.3.8-13.12mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"beagle-gui-0.3.8-13.12mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"beagle-gui-qt-0.3.8-13.12mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"beagle-libs-0.3.8-13.12mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"firefox-ext-beagle-0.3.8-13.12mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-af-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-be-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-beagle-0.3.8-13.12mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-bg-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-ca-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-cs-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-da-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-de-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-devel-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-el-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-en_GB-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-ar-2.0.0.22-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-ca-2.0.0.22-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-cs-2.0.0.22-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-de-2.0.0.22-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-el-2.0.0.22-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-es-2.0.0.22-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-es_AR-2.0.0.22-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-fi-2.0.0.22-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-fr-2.0.0.22-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-hu-2.0.0.22-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-it-2.0.0.22-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-ja-2.0.0.22-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-ko-2.0.0.22-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-nb-2.0.0.22-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-nl-2.0.0.22-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-pl-2.0.0.22-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-pt-2.0.0.22-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-pt_BR-2.0.0.22-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-ro-2.0.0.22-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-ru-2.0.0.22-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-sk-2.0.0.22-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-sl-2.0.0.22-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-sv-2.0.0.22-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-tr-2.0.0.22-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-zh_CN-2.0.0.22-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-enigmail-zh_TW-2.0.0.22-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-es_AR-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-es_ES-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-et_EE-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-eu-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-fi-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-fr-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-ga-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-gu_IN-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-he-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-hu-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-it-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-ja-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-ko-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-lt-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-mk-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-moztraybiff-1.2.4-1.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-nb_NO-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-nl-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-nn_NO-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-pa_IN-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-pl-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-pt_BR-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-pt_PT-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-ru-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-sk-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-sl-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-sv_SE-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-tr-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-uk-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-zh_CN-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mozilla-thunderbird-zh_TW-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"nsinstall-2.0.0.22-0.2mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.1", reference:"beagle-0.3.9-9.3mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"beagle-crawl-system-0.3.9-9.3mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"beagle-doc-0.3.9-9.3mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"beagle-epiphany-0.3.9-9.3mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"beagle-evolution-0.3.9-9.3mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"beagle-gui-0.3.9-9.3mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"beagle-gui-qt-0.3.9-9.3mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"beagle-libs-0.3.9-9.3mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"firefox-ext-beagle-0.3.9-9.3mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-af-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-be-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-beagle-0.3.9-9.3mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-bg-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-ca-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-cs-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-da-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-de-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-devel-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-el-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-en_GB-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-enigmail-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-enigmail-ar-2.0.0.22-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-enigmail-ca-2.0.0.22-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-enigmail-cs-2.0.0.22-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-enigmail-de-2.0.0.22-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-enigmail-el-2.0.0.22-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-enigmail-es-2.0.0.22-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-enigmail-es_AR-2.0.0.22-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-enigmail-fi-2.0.0.22-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-enigmail-fr-2.0.0.22-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-enigmail-hu-2.0.0.22-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-enigmail-it-2.0.0.22-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-enigmail-ja-2.0.0.22-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-enigmail-ko-2.0.0.22-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-enigmail-nb-2.0.0.22-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-enigmail-nl-2.0.0.22-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-enigmail-pl-2.0.0.22-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-enigmail-pt-2.0.0.22-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-enigmail-pt_BR-2.0.0.22-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-enigmail-ro-2.0.0.22-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-enigmail-ru-2.0.0.22-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-enigmail-sk-2.0.0.22-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-enigmail-sl-2.0.0.22-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-enigmail-sv-2.0.0.22-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-enigmail-tr-2.0.0.22-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-enigmail-zh_CN-2.0.0.22-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-enigmail-zh_TW-2.0.0.22-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-es_AR-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-es_ES-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-et_EE-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-eu-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-fi-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-fr-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-ga-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-gu_IN-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-he-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-hu-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-it-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-ja-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-ko-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-lt-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-mk-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-moztraybiff-1.2.4-4.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-nb_NO-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-nl-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-nn_NO-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-pa_IN-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-pl-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-pt_BR-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-pt_PT-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-ru-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-sk-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-sl-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-sv_SE-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-tr-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-uk-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-zh_CN-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mozilla-thunderbird-zh_TW-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nsinstall-2.0.0.22-0.2mdv2009.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
