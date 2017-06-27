#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0181. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51825);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/01/04 16:02:21 $");

  script_cve_id("CVE-2010-3450", "CVE-2010-3451", "CVE-2010-3452", "CVE-2010-3453", "CVE-2010-3454", "CVE-2010-3689", "CVE-2010-4253", "CVE-2010-4643");
  script_osvdb_id(70712, 70713, 70714, 70715);
  script_xref(name:"RHSA", value:"2011:0181");

  script_name(english:"RHEL 4 : openoffice.org and openoffice.org2 (RHSA-2011:0181)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openoffice.org and openoffice.org2 packages that fix multiple
security issues are now available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

OpenOffice.org is an office productivity suite that includes desktop
applications, such as a word processor, spreadsheet application,
presentation manager, formula editor, and a drawing program.

An array index error and an integer signedness error were found in the
way OpenOffice.org parsed certain Rich Text Format (RTF) files. An
attacker could use these flaws to create a specially crafted RTF file
that, when opened, would cause OpenOffice.org to crash or, possibly,
execute arbitrary code with the privileges of the user running
OpenOffice.org. (CVE-2010-3451, CVE-2010-3452)

A heap-based buffer overflow flaw and an array index error were found
in the way OpenOffice.org parsed certain Microsoft Office Word
documents. An attacker could use these flaws to create a specially
crafted Microsoft Office Word document that, when opened, would cause
OpenOffice.org to crash or, possibly, execute arbitrary code with the
privileges of the user running OpenOffice.org. (CVE-2010-3453,
CVE-2010-3454)

A heap-based buffer overflow flaw was found in the way OpenOffice.org
parsed certain TARGA (Truevision TGA) files. An attacker could use
this flaw to create a specially crafted TARGA file. If a document
containing this specially crafted TARGA file was opened, or if a user
tried to insert the file into an existing document, it would cause
OpenOffice.org to crash or, possibly, execute arbitrary code with the
privileges of the user running OpenOffice.org. (CVE-2010-4643)

A directory traversal flaw was found in the way OpenOffice.org handled
the installation of XSLT filter descriptions packaged in Java Archive
(JAR) files, as well as the installation of OpenOffice.org Extension
(.oxt) files. An attacker could use these flaws to create a specially
crafted XSLT filter description or extension file that, when opened,
would cause the OpenOffice.org Extension Manager to modify files
accessible to the user installing the JAR or extension file.
(CVE-2010-3450)

Red Hat would like to thank OpenOffice.org for reporting the
CVE-2010-3451, CVE-2010-3452, CVE-2010-3453, CVE-2010-3454, and
CVE-2010-4643 issues. Upstream acknowledges Dan Rosenberg of Virtual
Security Research as the original reporter of the CVE-2010-3451,
CVE-2010-3452, CVE-2010-3453, and CVE-2010-3454 issues.

All OpenOffice.org users are advised to upgrade to these updated
packages, which contain backported patches to correct these issues.
All running instances of OpenOffice.org applications must be restarted
for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3450.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3451.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3452.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3453.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3454.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-4643.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0181.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-emailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-graphicfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-javafilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-af_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-bg_BG");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-ca_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-cs_CZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-cy_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-da_DK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-el_GR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-et_EE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-eu_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-fi_FI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-ga_IE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-gl_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-gu_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-he_IL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-hi_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-hr_HR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-hu_HU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-ja_JP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-ko_KR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-lt_LT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-ms_MY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-nb_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-nn_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-pa_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-pl_PL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-pt_PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-sk_SK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-sl_SI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-sr_CS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-ta_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-th_TH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-tr_TR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-zu_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-testtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if (cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i386", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:0181";
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
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org-1.1.5-10.7.el4_8.10")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org-i18n-1.1.5-10.7.el4_8.10")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org-kde-1.1.5-10.7.el4_8.10")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org-libs-1.1.5-10.7.el4_8.10")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-base-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-calc-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-core-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-draw-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-emailmerge-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-graphicfilter-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-impress-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-javafilter-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-af_ZA-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-ar-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-bg_BG-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-bn-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-ca_ES-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-cs_CZ-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-cy_GB-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-da_DK-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-de-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-el_GR-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-es-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-et_EE-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-eu_ES-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-fi_FI-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-fr-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-ga_IE-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-gl_ES-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-gu_IN-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-he_IL-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-hi_IN-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-hr_HR-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-hu_HU-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-it-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-ja_JP-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-ko_KR-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-lt_LT-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-ms_MY-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-nb_NO-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-nl-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-nn_NO-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-pa_IN-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-pl_PL-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-pt_BR-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-pt_PT-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-ru-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-sk_SK-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-sl_SI-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-sr_CS-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-sv-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-ta_IN-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-th_TH-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-tr_TR-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-zh_CN-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-zh_TW-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-zu_ZA-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-math-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-pyuno-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-testtools-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-writer-2.0.4-5.7.0.6.1.el4_8.8")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-xsltfilter-2.0.4-5.7.0.6.1.el4_8.8")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openoffice.org / openoffice.org-i18n / openoffice.org-kde / etc");
  }
}
