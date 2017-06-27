#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0183. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51827);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/01/04 16:02:21 $");

  script_cve_id("CVE-2010-3450", "CVE-2010-3451", "CVE-2010-3452", "CVE-2010-3453", "CVE-2010-3454", "CVE-2010-3689", "CVE-2010-4253", "CVE-2010-4643");
  script_xref(name:"RHSA", value:"2011:0183");

  script_name(english:"RHEL 6 : openoffice.org (RHSA-2011:0183)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openoffice.org packages that fix multiple security issues and
one bug are now available for Red Hat Enterprise Linux 6.

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
parsed certain Microsoft Office PowerPoint files. An attacker could
use this flaw to create a specially crafted Microsoft Office
PowerPoint file that, when opened, would cause OpenOffice.org to crash
or, possibly, execute arbitrary code with the privileges of the user
running OpenOffice.org. (CVE-2010-4253)

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

A flaw was found in the script that launches OpenOffice.org. In some
situations, a '.' character could be included in the LD_LIBRARY_PATH
variable, allowing a local attacker to execute arbitrary code with the
privileges of the user running OpenOffice.org, if that user ran
OpenOffice.org from within an attacker-controlled directory.
(CVE-2010-3689)

Red Hat would like to thank OpenOffice.org for reporting the
CVE-2010-3451, CVE-2010-3452, CVE-2010-3453, CVE-2010-3454, and
CVE-2010-4643 issues; and Dmitri Gribenko for reporting the
CVE-2010-3689 issue. Upstream acknowledges Dan Rosenberg of Virtual
Security Research as the original reporter of the CVE-2010-3451,
CVE-2010-3452, CVE-2010-3453, and CVE-2010-3454 issues.

This update also fixes the following bug :

* OpenOffice.org did not create a lock file when opening a file that
was on a share mounted via SFTP. Additionally, if there was a lock
file, it was ignored. This could result in data loss if a file in this
situation was opened simultaneously by another user. (BZ#671087)

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
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3689.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-4253.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-4643.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0183.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-lb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-zh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:broffice.org-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:broffice.org-brand");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:broffice.org-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:broffice.org-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:broffice.org-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:broffice.org-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:broffice.org-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-base-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-brand");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-bsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-calc-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-draw-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-emailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-graphicfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-impress-core");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-el_GR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-en");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-mai_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ml_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-mr_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ms_MY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-nb_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-nn_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-nr_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-nso_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-or_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-pl_PL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-pt_PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-sk_SK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-sl_SI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ss_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-st_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ta_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-te_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-th_TH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-tn_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-tr_TR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ts_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ve_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-xh_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-zu_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-math-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-ogltrans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-opensymbol-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-pdfimport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-presentation-minimizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-presenter-screen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-report-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-rhino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-sdk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-testtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-wiki-publisher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-writer-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.0");

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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:0183";
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
  if (rpm_check(release:"RHEL6", reference:"autocorr-af-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-bg-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-cs-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-da-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-de-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-en-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-es-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-eu-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-fa-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-fi-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-fr-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-ga-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-hu-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-it-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-ja-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-ko-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-lb-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-lt-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-mn-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-nl-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-pl-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-pt-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-ru-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-sk-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-sl-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-sv-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-tr-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-vi-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"autocorr-zh-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"broffice.org-base-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"broffice.org-base-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"broffice.org-base-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"broffice.org-brand-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"broffice.org-brand-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"broffice.org-brand-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"broffice.org-calc-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"broffice.org-calc-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"broffice.org-calc-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"broffice.org-draw-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"broffice.org-draw-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"broffice.org-draw-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"broffice.org-impress-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"broffice.org-impress-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"broffice.org-impress-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"broffice.org-math-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"broffice.org-math-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"broffice.org-math-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"broffice.org-writer-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"broffice.org-writer-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"broffice.org-writer-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-base-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-base-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-base-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-base-core-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-base-core-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-base-core-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-brand-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-brand-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-brand-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-bsh-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-bsh-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-bsh-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-calc-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-calc-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-calc-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-calc-core-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-calc-core-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-calc-core-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-core-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-core-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-core-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"openoffice.org-debuginfo-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"openoffice.org-devel-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-draw-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-draw-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-draw-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-draw-core-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-draw-core-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-draw-core-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-emailmerge-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-emailmerge-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-emailmerge-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-graphicfilter-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-graphicfilter-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-graphicfilter-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-headless-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-headless-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-headless-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-impress-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-impress-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-impress-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-impress-core-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-impress-core-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-impress-core-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-javafilter-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-javafilter-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-javafilter-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-af_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-af_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-af_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-ar-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-ar-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-ar-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-as_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-as_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-as_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-bg_BG-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-bg_BG-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-bg_BG-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-bn-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-bn-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-bn-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-ca_ES-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-ca_ES-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-ca_ES-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-cs_CZ-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-cs_CZ-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-cs_CZ-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-cy_GB-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-cy_GB-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-cy_GB-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-da_DK-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-da_DK-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-da_DK-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-de-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-de-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-de-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-dz-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-dz-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-dz-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-el_GR-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-el_GR-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-el_GR-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-en-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-en-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-en-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-es-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-es-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-es-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-et_EE-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-et_EE-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-et_EE-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-eu_ES-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-eu_ES-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-eu_ES-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-fi_FI-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-fi_FI-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-fi_FI-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-fr-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-fr-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-fr-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-ga_IE-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-ga_IE-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-ga_IE-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-gl_ES-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-gl_ES-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-gl_ES-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-gu_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-gu_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-gu_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-he_IL-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-he_IL-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-he_IL-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-hi_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-hi_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-hi_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-hr_HR-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-hr_HR-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-hr_HR-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-hu_HU-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-hu_HU-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-hu_HU-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-it-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-it-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-it-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-ja_JP-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-ja_JP-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-ja_JP-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-kn_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-kn_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-kn_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-ko_KR-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-ko_KR-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-ko_KR-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-lt_LT-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-lt_LT-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-lt_LT-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-mai_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-mai_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-mai_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-ml_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-ml_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-ml_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-mr_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-mr_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-mr_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-ms_MY-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-ms_MY-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-ms_MY-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-nb_NO-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-nb_NO-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-nb_NO-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-nl-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-nl-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-nl-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-nn_NO-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-nn_NO-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-nn_NO-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-nr_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-nr_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-nr_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-nso_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-nso_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-nso_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-or_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-or_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-or_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-pa-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-pa-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-pa-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-pl_PL-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-pl_PL-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-pl_PL-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-pt_BR-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-pt_BR-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-pt_BR-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-pt_PT-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-pt_PT-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-pt_PT-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-ro-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-ro-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-ro-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-ru-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-ru-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-ru-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-sk_SK-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-sk_SK-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-sk_SK-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-sl_SI-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-sl_SI-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-sl_SI-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-sr-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-sr-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-sr-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-ss_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-ss_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-ss_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-st_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-st_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-st_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-sv-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-sv-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-sv-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-ta_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-ta_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-ta_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-te_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-te_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-te_IN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-th_TH-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-th_TH-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-th_TH-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-tn_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-tn_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-tn_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-tr_TR-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-tr_TR-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-tr_TR-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-ts_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-ts_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-ts_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-uk-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-uk-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-uk-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-ur-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-ur-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-ur-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-ve_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-ve_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-ve_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-xh_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-xh_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-xh_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-zh_CN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-zh_CN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-zh_CN-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-zh_TW-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-zh_TW-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-zh_TW-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-langpack-zu_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-langpack-zu_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-langpack-zu_ZA-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-math-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-math-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-math-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-math-core-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-math-core-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-math-core-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-ogltrans-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-ogltrans-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-ogltrans-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"openoffice.org-opensymbol-fonts-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-pdfimport-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-pdfimport-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-pdfimport-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-presentation-minimizer-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-presentation-minimizer-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-presentation-minimizer-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-presenter-screen-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-presenter-screen-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-presenter-screen-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-pyuno-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-pyuno-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-pyuno-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-report-builder-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-report-builder-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-report-builder-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-rhino-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-rhino-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-rhino-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-sdk-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-sdk-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-sdk-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-sdk-doc-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-sdk-doc-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-sdk-doc-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-testtools-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-testtools-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-testtools-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-ure-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-ure-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-ure-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-wiki-publisher-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-wiki-publisher-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-wiki-publisher-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-writer-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-writer-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-writer-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-writer-core-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-writer-core-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-writer-core-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openoffice.org-xsltfilter-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openoffice.org-xsltfilter-3.2.1-19.6.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openoffice.org-xsltfilter-3.2.1-19.6.el6_0.5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "autocorr-af / autocorr-bg / autocorr-cs / autocorr-da / autocorr-de / etc");
  }
}
