#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2589. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94552);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/01/10 20:46:33 $");

  script_cve_id("CVE-2016-4994");
  script_osvdb_id(140355);
  script_xref(name:"RHSA", value:"2016:2589");

  script_name(english:"RHEL 7 : gimp (RHSA-2016:2589)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for gimp and gimp-help is now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The GIMP (GNU Image Manipulation Program) is an image composition and
editing program. GIMP provides a large image manipulation toolbox,
including channel operations and layers, effects, sub-pixel imaging
and anti-aliasing, and conversions, all with multi-level undo.

The following packages have been upgraded to a newer upstream version:
gimp (2.8.16), gimp-help (2.8.2). (BZ#1298226, BZ#1370595)

Security Fix(es) :

* Multiple use-after-free vulnerabilities were found in GIMP in the
channel and layer properties parsing process when loading XCF files.
An attacker could create a specially crafted XCF file which could
cause GIMP to crash. (CVE-2016-4994)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-4994.html"
  );
  # https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e4086253"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-2589.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp-devel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp-help");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp-help-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp-help-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp-help-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp-help-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp-help-en_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp-help-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp-help-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp-help-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp-help-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp-help-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp-help-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp-help-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp-help-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp-help-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp-help-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp-help-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp-help-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gimp-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2016:2589";
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"gimp-2.8.16-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"gimp-2.8.16-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"gimp-debuginfo-2.8.16-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"gimp-devel-2.8.16-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"gimp-devel-tools-2.8.16-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"gimp-devel-tools-2.8.16-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"gimp-help-2.8.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"gimp-help-ca-2.8.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"gimp-help-da-2.8.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"gimp-help-de-2.8.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"gimp-help-el-2.8.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"gimp-help-en_GB-2.8.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"gimp-help-es-2.8.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"gimp-help-fr-2.8.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"gimp-help-it-2.8.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"gimp-help-ja-2.8.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"gimp-help-ko-2.8.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"gimp-help-nl-2.8.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"gimp-help-nn-2.8.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"gimp-help-pt_BR-2.8.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"gimp-help-ru-2.8.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"gimp-help-sl-2.8.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"gimp-help-sv-2.8.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"gimp-help-zh_CN-2.8.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"gimp-libs-2.8.16-3.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gimp / gimp-debuginfo / gimp-devel / gimp-devel-tools / gimp-help / etc");
  }
}
