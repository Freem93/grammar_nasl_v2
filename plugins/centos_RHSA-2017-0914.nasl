#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0914 and 
# CentOS Errata and Security Advisory 2017:0914 respectively.
#

include("compat.inc");

if (description)
{
  script_id(99381);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/04/19 13:30:59 $");

  script_cve_id("CVE-2017-3157");
  script_osvdb_id(152405);
  script_xref(name:"RHSA", value:"2017:0914");
  script_xref(name:"IAVB", value:"2017-B-0026");

  script_name(english:"CentOS 7 : libreoffice (CESA-2017:0914)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for libreoffice is now available for Red Hat Enterprise
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

Security Fix(es) :

* It was found that LibreOffice disclosed contents of a file specified
in an embedded object's preview. An attacker could potentially use
this flaw to expose details of a system running LibreOffice as an
online service via a crafted document. (CVE-2017-3157)

Bug Fix(es) :

* Previously, an improper resource management caused the LibreOffice
Calc spreadsheet application to terminate unexpectedly after closing a
dialog window with accessibility support enabled. The resource
management has been improved, and the described problem no longer
occurs. (BZ#1425536)

* Previously, when an incorrect password was entered for a password
protected document, the document has been considered as valid and a
fallback attempt to open it as plain text has been made. As a
consequence, it could appear that the document succesfully loaded,
while just the encrypted unreadable content was shown. A fix has been
made to terminate import attempts after entering incorrect password,
and now nothing is loaded when a wrong password is entered.
(BZ#1426348)

* Previously, an improper resource management caused the LibreOffice
Calc spreadsheet application to terminate unexpectedly during exit,
after the Text Import dialog for CSV (Comma-separated Value) files
closed, when accessibility support was enabled. The resource
management has been improved, and the described problem no longer
occurs. (BZ#1425535)"
  );
  # http://lists.centos.org/pipermail/centos-announce/2017-April/022359.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eb098cca"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/14");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-af-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-bg-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-ca-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-cs-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-da-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-de-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-en-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-es-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-fa-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-fi-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-fr-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-ga-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-hr-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-hu-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-is-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-it-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-ja-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-ko-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-lb-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-lt-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-mn-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-nl-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-pl-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-pt-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-ro-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-ru-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-sk-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-sl-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-sr-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-sv-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-tr-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-vi-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autocorr-zh-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-base-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-bsh-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-calc-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-core-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-draw-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-emailmerge-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-filters-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-gdb-debug-support-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-glade-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-graphicfilter-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-impress-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-af-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ar-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-as-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-bg-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-bn-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-br-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ca-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-cs-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-cy-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-da-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-de-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-dz-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-el-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-en-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-es-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-et-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-eu-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-fa-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-fi-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-fr-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ga-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-gl-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-gu-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-he-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-hi-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-hr-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-hu-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-it-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ja-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-kk-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-kn-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ko-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-lt-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-lv-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-mai-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ml-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-mr-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-nb-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-nl-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-nn-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-nr-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-nso-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-or-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-pa-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-pl-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-pt-BR-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-pt-PT-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ro-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ru-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-si-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-sk-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-sl-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-sr-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ss-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-st-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-sv-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ta-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-te-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-th-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-tn-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-tr-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ts-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-uk-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-ve-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-xh-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-zh-Hans-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-zh-Hant-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-langpack-zu-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-librelogo-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-math-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-nlpsolver-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-officebean-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-ogltrans-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-opensymbol-fonts-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-pdfimport-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-postgresql-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-pyuno-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-rhino-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-sdk-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-sdk-doc-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-ure-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-wiki-publisher-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-writer-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreoffice-xsltfilter-5.0.6.2-5.el7_3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
