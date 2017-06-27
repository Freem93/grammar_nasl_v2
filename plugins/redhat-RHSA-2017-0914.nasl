#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0914. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99342);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/04/19 13:30:59 $");

  script_cve_id("CVE-2017-3157");
  script_osvdb_id(152405);
  script_xref(name:"RHSA", value:"2017:0914");
  script_xref(name:"IAVB", value:"2017-B-0026");

  script_name(english:"RHEL 7 : libreoffice (RHSA-2017:0914)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
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
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2017-3157.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2017-0914.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-lb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-zh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-bsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-emailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-gdb-debug-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-glade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-graphicfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-pt-PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-zh-Hans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-zh-Hant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-librelogo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-nlpsolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-ogltrans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-opensymbol-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-pdfimport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-rhino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-sdk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-wiki-publisher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/13");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:0914";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL7", reference:"autocorr-af-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-bg-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-ca-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-cs-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-da-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-de-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-en-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-es-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-fa-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-fi-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-fr-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-ga-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-hr-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-hu-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-is-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-it-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-ja-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-ko-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-lb-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-lt-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-mn-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-nl-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-pl-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-pt-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-ro-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-ru-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-sk-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-sl-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-sr-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-sv-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-tr-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-vi-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"autocorr-zh-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-base-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-bsh-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-calc-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-core-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-debuginfo-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-draw-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-emailmerge-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-filters-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-gdb-debug-support-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-glade-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-graphicfilter-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-impress-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-af-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-ar-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-as-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-bg-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-bn-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-br-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-ca-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-cs-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-cy-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-da-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-de-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-dz-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-el-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-en-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-es-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-et-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-eu-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-fa-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-fi-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-fr-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-ga-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-gl-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-gu-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-he-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-hi-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-hr-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-hu-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-it-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-ja-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-kk-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-kn-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-ko-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-lt-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-lv-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-mai-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-ml-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-mr-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-nb-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-nl-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-nn-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-nr-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-nso-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-or-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-pa-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-pl-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-pt-BR-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-pt-PT-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-ro-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-ru-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-si-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-sk-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-sl-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-sr-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-ss-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-st-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-sv-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-ta-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-te-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-th-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-tn-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-tr-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-ts-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-uk-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-ve-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-xh-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-zh-Hans-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-zh-Hant-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-zu-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-librelogo-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-math-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-nlpsolver-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-officebean-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-ogltrans-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libreoffice-opensymbol-fonts-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-pdfimport-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-postgresql-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-pyuno-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-rhino-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-sdk-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-sdk-doc-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-ure-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-wiki-publisher-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-writer-5.0.6.2-5.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-xsltfilter-5.0.6.2-5.el7_3.1")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "autocorr-af / autocorr-bg / autocorr-ca / autocorr-cs / autocorr-da / etc");
  }
}
