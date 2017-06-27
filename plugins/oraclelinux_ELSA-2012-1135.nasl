#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:1135 and 
# Oracle Linux Security Advisory ELSA-2012-1135 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68591);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 17:07:16 $");

  script_cve_id("CVE-2012-2665");
  script_bugtraq_id(54769);
  script_osvdb_id(84440, 84441, 84442);
  script_xref(name:"RHSA", value:"2012:1135");

  script_name(english:"Oracle Linux 6 : libreoffice (ELSA-2012-1135)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:1135 :

Updated libreoffice packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

LibreOffice is an open source, community-developed office productivity
suite. It includes the key desktop applications, such as a word
processor, spreadsheet application, presentation manager, formula
editor, and a drawing program.

Multiple heap-based buffer overflow flaws were found in the way
LibreOffice processed encryption information in the manifest files of
OpenDocument Format files. An attacker could provide a specially
crafted OpenDocument Format file that, when opened in a LibreOffice
application, would cause the application to crash or, potentially,
execute arbitrary code with the privileges of the user running the
application. (CVE-2012-2665)

Upstream acknowledges Timo Warns as the original reporter of these
issues.

All LibreOffice users are advised to upgrade to these updated
packages, which contain backported patches to correct these issues.
All running instances of LibreOffice applications must be restarted
for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-August/002968.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libreoffice packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-lb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autocorr-pt");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-gdb-debug-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-graphicfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-javafilter");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-ogltrans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-opensymbol-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-pdfimport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-presentation-minimizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-presenter-screen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-report-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-rhino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-sdk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-testtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-wiki-publisher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreoffice-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL6", reference:"autocorr-af-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-bg-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-cs-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-da-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-de-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-en-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-es-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-eu-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-fa-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-fi-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-fr-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-ga-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-hr-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-hu-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-it-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-ja-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-ko-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-lb-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-lt-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-mn-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-nl-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-pl-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-pt-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-ru-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-sk-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-sl-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-sr-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-sv-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-tr-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-vi-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"autocorr-zh-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-base-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-bsh-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-calc-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-core-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-draw-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-emailmerge-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-gdb-debug-support-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-graphicfilter-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-headless-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-impress-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-javafilter-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-af-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ar-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-as-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-bg-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-bn-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ca-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-cs-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-cy-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-da-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-de-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-dz-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-el-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-en-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-es-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-et-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-eu-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-fi-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-fr-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ga-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-gl-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-gu-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-he-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-hi-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-hr-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-hu-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-it-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ja-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-kn-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ko-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-lt-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-mai-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ml-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-mr-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ms-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-nb-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-nl-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-nn-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-nr-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-nso-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-or-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-pa-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-pl-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-pt-BR-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-pt-PT-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ro-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ru-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-sk-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-sl-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-sr-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ss-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-st-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-sv-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ta-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-te-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-th-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-tn-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-tr-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ts-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-uk-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ur-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-ve-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-xh-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-zh-Hans-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-zh-Hant-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-langpack-zu-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-math-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-ogltrans-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-opensymbol-fonts-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-pdfimport-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-presentation-minimizer-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-presenter-screen-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-pyuno-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-report-builder-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-rhino-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-sdk-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-sdk-doc-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-testtools-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-ure-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-wiki-publisher-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-writer-3.4.5.2-16.1.0.1.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libreoffice-xsltfilter-3.4.5.2-16.1.0.1.el6_3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "autocorr-af / autocorr-bg / autocorr-cs / autocorr-da / autocorr-de / etc");
}
