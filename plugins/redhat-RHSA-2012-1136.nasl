#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1136. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61390);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/05 16:04:22 $");

  script_cve_id("CVE-2012-2665");
  script_osvdb_id(84440, 84441, 84442);
  script_xref(name:"RHSA", value:"2012:1136");

  script_name(english:"RHEL 5 : openoffice.org (RHSA-2012:1136)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openoffice.org packages that fix multiple security issues are
now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

OpenOffice.org is an office productivity suite that includes desktop
applications, such as a word processor, spreadsheet application,
presentation manager, formula editor, and a drawing program.

Multiple heap-based buffer overflow flaws were found in the way
OpenOffice.org processed encryption information in the manifest files
of OpenDocument Format files. An attacker could provide a specially
crafted OpenDocument Format file that, when opened in an
OpenOffice.org application, would cause the application to crash or,
potentially, execute arbitrary code with the privileges of the user
running the application. (CVE-2012-2665)

Upstream acknowledges Timo Warns as the original reporter of these
issues.

All OpenOffice.org users are advised to upgrade to these updated
packages, which contain backported patches to correct these issues.
All running instances of OpenOffice.org applications must be restarted
for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2665.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-1136.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-emailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-graphicfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-javafilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-af_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-as_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-bg_BG");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ca_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-cs_CZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-cy_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-da_DK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-el_GR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-et_EE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-eu_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-fi_FI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ga_IE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-gl_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-gu_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-he_IL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-hi_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-hr_HR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-hu_HU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ja_JP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-kn_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ko_KR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-lt_LT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ml_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-mr_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ms_MY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-nb_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-nn_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-nr_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-nso_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-or_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-pa_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-pl_PL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-pt_PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-sk_SK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-sl_SI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-sr_CS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ss_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-st_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ta_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-te_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-th_TH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-tn_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-tr_TR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ts_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ve_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-xh_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-zu_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-sdk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-testtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:1136";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-base-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-base-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-calc-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-calc-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-core-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-core-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-debuginfo-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-debuginfo-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-draw-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-draw-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-emailmerge-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-emailmerge-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-graphicfilter-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-graphicfilter-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-headless-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-headless-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-impress-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-impress-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-javafilter-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-javafilter-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-af_ZA-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-af_ZA-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-ar-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-ar-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-as_IN-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-as_IN-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-bg_BG-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-bg_BG-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-bn-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-bn-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-ca_ES-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-ca_ES-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-cs_CZ-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-cs_CZ-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-cy_GB-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-cy_GB-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-da_DK-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-da_DK-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-de-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-de-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-el_GR-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-el_GR-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-es-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-es-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-et_EE-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-et_EE-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-eu_ES-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-eu_ES-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-fi_FI-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-fi_FI-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-fr-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-fr-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-ga_IE-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-ga_IE-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-gl_ES-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-gl_ES-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-gu_IN-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-gu_IN-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-he_IL-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-he_IL-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-hi_IN-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-hi_IN-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-hr_HR-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-hr_HR-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-hu_HU-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-hu_HU-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-it-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-it-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-ja_JP-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-ja_JP-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-kn_IN-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-kn_IN-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-ko_KR-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-ko_KR-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-lt_LT-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-lt_LT-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-ml_IN-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-ml_IN-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-mr_IN-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-mr_IN-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-ms_MY-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-ms_MY-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-nb_NO-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-nb_NO-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-nl-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-nl-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-nn_NO-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-nn_NO-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-nr_ZA-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-nr_ZA-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-nso_ZA-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-nso_ZA-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-or_IN-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-or_IN-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-pa_IN-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-pa_IN-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-pl_PL-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-pl_PL-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-pt_BR-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-pt_BR-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-pt_PT-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-pt_PT-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-ru-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-ru-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-sk_SK-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-sk_SK-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-sl_SI-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-sl_SI-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-sr_CS-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-sr_CS-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-ss_ZA-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-ss_ZA-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-st_ZA-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-st_ZA-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-sv-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-sv-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-ta_IN-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-ta_IN-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-te_IN-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-te_IN-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-th_TH-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-th_TH-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-tn_ZA-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-tn_ZA-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-tr_TR-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-tr_TR-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-ts_ZA-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-ts_ZA-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-ur-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-ur-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-ve_ZA-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-ve_ZA-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-xh_ZA-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-xh_ZA-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-zh_CN-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-zh_CN-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-zh_TW-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-zh_TW-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-zu_ZA-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-zu_ZA-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-math-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-math-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-pyuno-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-pyuno-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-sdk-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-sdk-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-sdk-doc-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-sdk-doc-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-testtools-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-testtools-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-ure-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-ure-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-writer-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-writer-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-xsltfilter-3.1.1-19.10.el5_8.4")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-xsltfilter-3.1.1-19.10.el5_8.4")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openoffice.org-base / openoffice.org-calc / openoffice.org-core / etc");
  }
}
