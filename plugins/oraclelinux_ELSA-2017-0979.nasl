#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2017:0979 and 
# Oracle Linux Security Advisory ELSA-2017-0979 respectively.
#

include("compat.inc");

if (description)
{
  script_id(99451);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/04/21 16:53:27 $");

  script_cve_id("CVE-2017-3157");
  script_osvdb_id(152405);
  script_xref(name:"RHSA", value:"2017:0979");
  script_xref(name:"IAVB", value:"2017-B-0026");

  script_name(english:"Oracle Linux 6 : libreoffice (ELSA-2017-0979)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2017:0979 :

An update for libreoffice is now available for Red Hat Enterprise
Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

LibreOffice is an open source, community-developed office productivity
suite. It includes key desktop applications, such as a word processor,
a spreadsheet, a presentation manager, a formula editor, and a drawing
program. LibreOffice replaces OpenOffice and provides a similar but
enhanced and extended office suite.

Security Fix(es) :

* It was found that LibreOffice disclosed contents of a file specified
in an embedded object's preview. An attacker could potentially use
this flaw to expose details of a system running LibreOffice as an
online service via a crafted document. (CVE-2017-3157)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-April/006869.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libreoffice packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-bn");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ms");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-langpack-ur");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-rhino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-sdk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-wiki-publisher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"autocorr-af-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-bg-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-ca-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-cs-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-da-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-de-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-en-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-es-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-fa-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-fi-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-fr-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-ga-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-hr-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-hu-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-is-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-it-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-ja-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-ko-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-lb-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-lt-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-mn-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-nl-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-pl-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-pt-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-ro-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-ru-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-sk-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-sl-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-sr-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-sv-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-tr-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-vi-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-zh-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-base-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-bsh-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-calc-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-core-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-draw-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-emailmerge-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-filters-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-gdb-debug-support-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-glade-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-graphicfilter-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-headless-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-impress-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-af-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ar-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-as-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-bg-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-bn-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ca-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-cs-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-cy-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-da-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-de-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-dz-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-el-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-en-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-es-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-et-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-eu-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-fi-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-fr-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ga-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-gl-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-gu-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-he-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-hi-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-hr-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-hu-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-it-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ja-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-kn-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ko-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-lt-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-mai-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ml-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-mr-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ms-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-nb-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-nl-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-nn-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-nr-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-nso-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-or-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-pa-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-pl-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-pt-BR-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-pt-PT-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ro-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ru-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-sk-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-sl-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-sr-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ss-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-st-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-sv-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ta-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-te-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-th-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-tn-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-tr-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ts-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-uk-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ur-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ve-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-xh-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-zh-Hans-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-zh-Hant-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-zu-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-librelogo-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-math-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-nlpsolver-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-officebean-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-ogltrans-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-opensymbol-fonts-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-pdfimport-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-pyuno-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-rhino-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-sdk-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-sdk-doc-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-ure-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-wiki-publisher-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-writer-4.3.7.2-2.0.1.el6_9.1")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-xsltfilter-4.3.7.2-2.0.1.el6_9.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "autocorr-af / autocorr-bg / autocorr-ca / autocorr-cs / autocorr-da / etc");
}
