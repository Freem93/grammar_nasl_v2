#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:2579 and 
# Oracle Linux Security Advisory ELSA-2016-2579 respectively.
#

include("compat.inc");

if (description)
{
  script_id(94701);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/12/07 21:08:17 $");

  script_cve_id("CVE-2016-0794", "CVE-2016-0795");
  script_osvdb_id(134627, 134628);
  script_xref(name:"RHSA", value:"2016:2579");

  script_name(english:"Oracle Linux 7 : libreoffice (ELSA-2016-2579)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:2579 :

An update for libreoffice is now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

LibreOffice is an open source, community-developed office productivity
suite. It includes key desktop applications, such as a word processor,
a spreadsheet, a presentation manager, a formula editor, and a drawing
program. LibreOffice replaces OpenOffice and provides a similar but
enhanced and extended office suite.

The following packages have been upgraded to a newer upstream version:
libreoffice (5.0.6.2). (BZ#1290148)

Security Fix(es) :

* Multiple flaws were found in the Lotus Word Pro (LWP) document
format parser in LibreOffice. By tricking a user into opening a
specially crafted LWP document, an attacker could possibly use this
flaw to execute arbitrary code with the privileges of the user opening
the file. (CVE-2016-0794, CVE-2016-0795)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-November/006467.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libreoffice packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-lb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-zh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libcmis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libcmis-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libcmis-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpagemaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpagemaker-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpagemaker-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpagemaker-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-bsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-emailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-gdb-debug-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-glade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-graphicfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-pt-PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-zh-Hans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-zh-Hant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-librelogo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-nlpsolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-ogltrans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-opensymbol-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-pdfimport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-rhino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-sdk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-wiki-publisher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mdds-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-af-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-bg-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-ca-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-cs-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-da-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-de-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-en-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-es-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-fa-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-fi-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-fr-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-ga-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-hr-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-hu-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-is-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-it-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-ja-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-ko-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-lb-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-lt-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-mn-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-nl-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-pl-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-pt-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-ro-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-ru-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-sk-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-sl-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-sr-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-sv-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-tr-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-vi-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"autocorr-zh-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libcmis-0.5.1-2.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libcmis-devel-0.5.1-2.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libcmis-tools-0.5.1-2.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libpagemaker-0.0.3-1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libpagemaker-devel-0.0.3-1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libpagemaker-doc-0.0.3-1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libpagemaker-tools-0.0.3-1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-base-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-bsh-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-calc-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-core-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-draw-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-emailmerge-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-filters-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-gdb-debug-support-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-glade-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-graphicfilter-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-impress-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-af-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-ar-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-as-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-bg-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-bn-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-br-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-ca-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-cs-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-cy-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-da-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-de-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-dz-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-el-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-en-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-es-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-et-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-eu-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-fa-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-fi-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-fr-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-ga-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-gl-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-gu-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-he-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-hi-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-hr-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-hu-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-it-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-ja-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-kk-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-kn-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-ko-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-lt-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-lv-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-mai-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-ml-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-mr-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-nb-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-nl-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-nn-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-nr-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-nso-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-or-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-pa-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-pl-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-pt-BR-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-pt-PT-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-ro-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-ru-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-si-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-sk-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-sl-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-sr-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-ss-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-st-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-sv-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-ta-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-te-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-th-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-tn-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-tr-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-ts-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-uk-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-ve-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-xh-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-zh-Hans-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-zh-Hant-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-langpack-zu-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-librelogo-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-math-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-nlpsolver-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-officebean-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-ogltrans-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-opensymbol-fonts-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-pdfimport-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-postgresql-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-pyuno-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-rhino-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-sdk-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-sdk-doc-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-ure-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-wiki-publisher-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-writer-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libreoffice-xsltfilter-5.0.6.2-3.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mdds-devel-0.12.1-1.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "autocorr-af / autocorr-bg / autocorr-ca / autocorr-cs / autocorr-da / etc");
}
