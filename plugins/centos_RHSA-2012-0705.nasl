#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0705 and 
# CentOS Errata and Security Advisory 2012:0705 respectively.
#

include("compat.inc");

if (description)
{
  script_id(59378);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/05/19 23:52:01 $");

  script_cve_id("CVE-2012-1149", "CVE-2012-2334");
  script_bugtraq_id(53570);
  script_xref(name:"RHSA", value:"2012:0705");

  script_name(english:"CentOS 5 / 6 : openoffice.org (CESA-2012:0705)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openoffice.org packages that fix multiple security issues are
now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

OpenOffice.org is an office productivity suite that includes desktop
applications, such as a word processor, spreadsheet application,
presentation manager, formula editor, and a drawing program.

An integer overflow flaw, leading to a buffer overflow, was found in
the way OpenOffice.org processed an invalid Escher graphics records
length in Microsoft Office PowerPoint documents. An attacker could
provide a specially crafted Microsoft Office PowerPoint document that,
when opened, would cause OpenOffice.org to crash or, potentially,
execute arbitrary code with the privileges of the user running
OpenOffice.org. (CVE-2012-2334)

Multiple integer overflow flaws, leading to heap-based buffer
overflows, were found in the JPEG, PNG, and BMP image file reader
implementations in OpenOffice.org. An attacker could provide a
specially crafted JPEG, PNG, or BMP image file that, when opened in an
OpenOffice.org application, would cause the application to crash or,
potentially, execute arbitrary code with the privileges of the user
running the application. (CVE-2012-1149)

Upstream acknowledges Sven Jacobi as the original reporter of
CVE-2012-2334, and Tielei Wang via Secunia SVCRP as the original
reporter of CVE-2012-1149.

All OpenOffice.org users are advised to upgrade to these updated
packages, which contain backported patches to correct these issues.
All running instances of OpenOffice.org applications must be restarted
for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-June/018665.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?945b8b1c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-June/018666.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?44777be9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openoffice.org packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autocorr-zh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:broffice.org-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:broffice.org-brand");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:broffice.org-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:broffice.org-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:broffice.org-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:broffice.org-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:broffice.org-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-base-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-brand");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-bsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-calc-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-draw-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-emailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-graphicfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-impress-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-javafilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-af_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-as_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-bg_BG");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ca_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-cs_CZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-cy_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-da_DK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-el_GR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-et_EE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-eu_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-fi_FI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ga_IE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-gl_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-gu_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-he_IL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-hi_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-hr_HR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-hu_HU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ja_JP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-kn_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ko_KR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-lt_LT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-mai_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ml_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-mr_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ms_MY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-nb_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-nn_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-nr_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-nso_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-or_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-pa_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-pl_PL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-pt_PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-sk_SK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-sl_SI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-sr_CS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ss_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-st_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ta_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-te_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-th_TH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-tn_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-tr_TR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ts_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ve_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-xh_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-zu_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-math-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-ogltrans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-opensymbol-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-pdfimport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-presentation-minimizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-presenter-screen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-report-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-rhino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-sdk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-testtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-wiki-publisher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-writer-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-base-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-calc-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-core-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-draw-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-emailmerge-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-graphicfilter-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-headless-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-impress-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-javafilter-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-af_ZA-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ar-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-as_IN-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-bg_BG-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-bn-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ca_ES-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-cs_CZ-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-cy_GB-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-da_DK-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-de-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-el_GR-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-es-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-et_EE-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-eu_ES-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-fi_FI-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-fr-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ga_IE-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-gl_ES-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-gu_IN-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-he_IL-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-hi_IN-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-hr_HR-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-hu_HU-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-it-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ja_JP-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-kn_IN-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ko_KR-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-lt_LT-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ml_IN-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-mr_IN-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ms_MY-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-nb_NO-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-nl-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-nn_NO-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-nr_ZA-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-nso_ZA-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-or_IN-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-pa_IN-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-pl_PL-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-pt_BR-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-pt_PT-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ru-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-sk_SK-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-sl_SI-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-sr_CS-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ss_ZA-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-st_ZA-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-sv-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ta_IN-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-te_IN-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-th_TH-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-tn_ZA-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-tr_TR-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ts_ZA-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ur-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ve_ZA-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-xh_ZA-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-zh_CN-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-zh_TW-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-zu_ZA-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-math-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-pyuno-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-sdk-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-sdk-doc-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-testtools-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-ure-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-writer-3.1.1-19.10.el5_8.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-xsltfilter-3.1.1-19.10.el5_8.3")) flag++;

if (rpm_check(release:"CentOS-6", reference:"autocorr-af-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-bg-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-cs-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-da-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-de-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-en-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-es-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-eu-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-fa-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-fi-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-fr-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-ga-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-hu-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-it-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-ja-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-ko-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-lb-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-lt-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-mn-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-nl-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-pl-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-pt-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-ru-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-sk-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-sl-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-sv-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-tr-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-vi-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"autocorr-zh-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"broffice.org-base-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"broffice.org-brand-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"broffice.org-calc-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"broffice.org-draw-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"broffice.org-impress-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"broffice.org-math-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"broffice.org-writer-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-base-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-base-core-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-brand-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-bsh-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-calc-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-calc-core-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-core-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-devel-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-draw-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-draw-core-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-emailmerge-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-graphicfilter-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-headless-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-impress-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-impress-core-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-javafilter-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-af_ZA-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-ar-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-as_IN-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-bg_BG-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-bn-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-ca_ES-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-cs_CZ-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-cy_GB-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-da_DK-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-de-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-dz-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-el_GR-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-en-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-es-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-et_EE-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-eu_ES-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-fi_FI-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-fr-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-ga_IE-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-gl_ES-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-gu_IN-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-he_IL-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-hi_IN-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-hr_HR-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-hu_HU-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-it-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-ja_JP-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-kn_IN-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-ko_KR-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-lt_LT-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-mai_IN-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-ml_IN-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-mr_IN-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-ms_MY-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-nb_NO-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-nl-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-nn_NO-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-nr_ZA-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-nso_ZA-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-or_IN-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-pa-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-pl_PL-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-pt_BR-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-pt_PT-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-ro-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-ru-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-sk_SK-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-sl_SI-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-sr-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-ss_ZA-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-st_ZA-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-sv-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-ta_IN-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-te_IN-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-th_TH-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-tn_ZA-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-tr_TR-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-ts_ZA-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-uk-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-ur-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-ve_ZA-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-xh_ZA-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-zh_CN-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-zh_TW-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-langpack-zu_ZA-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-math-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-math-core-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-ogltrans-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-opensymbol-fonts-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-pdfimport-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-presentation-minimizer-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-presenter-screen-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-pyuno-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-report-builder-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-rhino-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-sdk-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-sdk-doc-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-testtools-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-ure-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-wiki-publisher-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-writer-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-writer-core-3.2.1-19.6.el6_2.7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openoffice.org-xsltfilter-3.2.1-19.6.el6_2.7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
