#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2619 and 
# CentOS Errata and Security Advisory 2015:2619 respectively.
#

include("compat.inc");

if (description)
{
  script_id(87358);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/05/20 13:54:06 $");

  script_cve_id("CVE-2015-4551", "CVE-2015-5212", "CVE-2015-5213", "CVE-2015-5214");
  script_osvdb_id(129856, 129857, 129858, 129859);
  script_xref(name:"RHSA", value:"2015:2619");

  script_name(english:"CentOS 6 / 7 : libreoffice (CESA-2015:2619)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libreoffice packages that fixes multiple security issues are
now available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

LibreOffice is an open source, community-developed office productivity
suite. It includes key desktop applications, such as a word processor,
a spreadsheet, a presentation manager, a formula editor, and a drawing
program. LibreOffice replaces OpenOffice and provides a similar but
enhanced and extended office suite.

It was discovered that LibreOffice did not properly restrict automatic
link updates. By tricking a victim into opening specially crafted
documents, an attacker could possibly use this flaw to disclose
contents of files accessible by the victim. (CVE-2015-4551)

An integer underflow flaw leading to a heap-based buffer overflow when
parsing PrinterSetup data was discovered. By tricking a user into
opening a specially crafted document, an attacker could possibly
exploit this flaw to execute arbitrary code with the privileges of the
user opening the file. (CVE-2015-5212)

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way LibreOffice processed certain Microsoft Word .doc
files. By tricking a user into opening a specially crafted Microsoft
Word .doc document, an attacker could possibly use this flaw to
execute arbitrary code with the privileges of the user opening the
file. (CVE-2015-5213)

It was discovered that LibreOffice did not properly sanity check
bookmark indexes. By tricking a user into opening a specially crafted
document, an attacker could possibly use this flaw to execute
arbitrary code with the privileges of the user opening the file.
(CVE-2015-5214)

All libreoffice users are advised to upgrade to these updated
packages, which contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-December/021521.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb0a2845"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-December/021522.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?65d9e1d8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libreoffice packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-lb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-ro");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-gdb-debug-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-glade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-graphicfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-br");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-fa");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-lv");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-langpack-si");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-librelogo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-nlpsolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-ogltrans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-opensymbol-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-pdfimport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-rhino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-sdk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-wiki-publisher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreoffice-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"autocorr-af-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-bg-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-ca-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-cs-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-da-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-de-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-en-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-es-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-fa-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-fi-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-fr-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-ga-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-hr-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-hu-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-is-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-it-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-ja-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-ko-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-lb-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-lt-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-mn-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-nl-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-pl-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-pt-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-ro-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-ru-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-sk-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-sl-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-sr-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-sv-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-tr-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-vi-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-zh-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-base-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-bsh-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-calc-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-core-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-draw-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-emailmerge-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-filters-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-gdb-debug-support-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-glade-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-graphicfilter-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-headless-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-impress-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-af-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ar-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-as-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-bg-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-bn-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ca-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-cs-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-cy-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-da-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-de-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-dz-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-el-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-en-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-es-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-et-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-eu-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-fi-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-fr-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ga-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-gl-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-gu-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-he-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-hi-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-hr-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-hu-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-it-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ja-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-kn-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ko-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-lt-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-mai-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ml-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-mr-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ms-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-nb-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-nl-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-nn-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-nr-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-nso-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-or-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-pa-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-pl-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-pt-BR-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-pt-PT-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ro-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ru-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-sk-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-sl-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-sr-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ss-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-st-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-sv-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ta-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-te-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-th-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-tn-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-tr-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ts-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-uk-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ur-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-ve-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-xh-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-zh-Hans-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-zh-Hant-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-langpack-zu-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-librelogo-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-math-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-nlpsolver-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-ogltrans-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-opensymbol-fonts-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-pdfimport-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-pyuno-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-rhino-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-sdk-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-sdk-doc-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-ure-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-wiki-publisher-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-writer-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreoffice-xsltfilter-4.2.8.2-11.el6_7.1")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-af-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-bg-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-ca-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-cs-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-da-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-de-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-en-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-es-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-fa-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-fi-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-fr-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-ga-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-hr-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-hu-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-is-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-it-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-ja-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-ko-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-lb-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-lt-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-mn-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-nl-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-pl-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-pt-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-ro-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-ru-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-sk-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-sl-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-sr-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-sv-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-tr-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-vi-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-zh-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-base-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-bsh-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-calc-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-core-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-draw-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-emailmerge-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-filters-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-gdb-debug-support-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-glade-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-graphicfilter-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-headless-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-impress-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-af-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ar-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-as-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-bg-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-bn-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-br-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ca-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-cs-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-cy-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-da-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-de-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-dz-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-el-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-en-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-es-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-et-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-eu-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-fa-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-fi-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-fr-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ga-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-gl-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-gu-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-he-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-hi-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-hr-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-hu-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-it-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ja-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-kk-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-kn-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ko-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-lt-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-lv-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-mai-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ml-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-mr-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-nb-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-nl-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-nn-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-nr-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-nso-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-or-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-pa-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-pl-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-pt-BR-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-pt-PT-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ro-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ru-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-si-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-sk-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-sl-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-sr-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ss-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-st-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-sv-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ta-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-te-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-th-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-tn-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-tr-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ts-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-uk-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ve-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-xh-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-zh-Hans-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-zh-Hant-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-zu-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-librelogo-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-math-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-nlpsolver-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-officebean-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-ogltrans-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-opensymbol-fonts-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-pdfimport-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-postgresql-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-pyuno-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-rhino-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-sdk-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-sdk-doc-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-ure-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-wiki-publisher-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-writer-4.3.7.2-5.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-xsltfilter-4.3.7.2-5.el7_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
