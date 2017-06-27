#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1135 and 
# CentOS Errata and Security Advisory 2012:1135 respectively.
#

include("compat.inc");

if (description)
{
  script_id(61397);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/16 19:09:25 $");

  script_cve_id("CVE-2012-2665");
  script_osvdb_id(84440, 84441, 84442);
  script_xref(name:"RHSA", value:"2012:1135");

  script_name(english:"CentOS 6 : libreoffice (CESA-2012:1135)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libreoffice packages that fix multiple security issues are now
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
  # http://lists.centos.org/pipermail/centos-announce/2012-August/018781.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2965c68"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libreoffice packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-lb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-zh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-bsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-emailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-gdb-debug-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-graphicfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-javafilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-pt-PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-zh-Hans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-zh-Hant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-ogltrans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-opensymbol-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-pdfimport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-presentation-minimizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-presenter-screen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-report-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-rhino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-sdk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-testtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-wiki-publisher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"autocorr-af-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-bg-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-cs-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-da-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-de-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-en-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-es-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-eu-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-fa-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-fi-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-fr-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-ga-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-hr-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-hu-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-it-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-ja-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-ko-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-lb-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-lt-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-mn-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-nl-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-pl-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-pt-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-ru-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-sk-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-sl-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-sr-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-sv-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-tr-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-vi-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-zh-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-base-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-bsh-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-calc-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-core-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-draw-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-emailmerge-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-gdb-debug-support-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-graphicfilter-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-headless-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-impress-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-javafilter-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-af-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ar-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-as-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-bg-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-bn-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ca-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-cs-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-cy-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-da-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-de-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-dz-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-el-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-en-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-es-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-et-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-eu-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-fi-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-fr-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ga-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-gl-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-gu-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-he-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-hi-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-hr-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-hu-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-it-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ja-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-kn-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ko-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-lt-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-mai-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ml-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-mr-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ms-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-nb-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-nl-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-nn-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-nr-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-nso-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-or-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-pa-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-pl-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-pt-BR-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-pt-PT-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ro-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ru-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-sk-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-sl-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-sr-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ss-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-st-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-sv-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ta-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-te-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-th-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-tn-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-tr-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ts-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-uk-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ur-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ve-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-xh-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-zh-Hans-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-zh-Hant-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-zu-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-math-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-ogltrans-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-opensymbol-fonts-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-pdfimport-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-presentation-minimizer-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-presenter-screen-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-pyuno-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-report-builder-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-rhino-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-sdk-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-sdk-doc-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-testtools-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-ure-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-wiki-publisher-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-writer-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-xsltfilter-3.4.5.2-16.1.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
