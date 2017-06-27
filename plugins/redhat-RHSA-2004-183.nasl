#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:183. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12493);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/28 17:44:44 $");

  script_cve_id("CVE-2004-0109", "CVE-2004-0424");
  script_xref(name:"RHSA", value:"2004:183");

  script_name(english:"RHEL 3 : kernel (RHSA-2004:183)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix two privilege escalation
vulnerabilities are now available.

The Linux kernel handles the basic functions of the operating system.

iSEC Security Research discovered a flaw in the ip_setsockopt()
function code of the Linux kernel versions 2.4.22 to 2.4.25 inclusive.
This flaw also affects the 2.4.21 kernel in Red Hat Enterprise Linux 3
which contained a backported version of the affected code. A local
user could use this flaw to gain root privileges. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2004-0424 to this issue.

iDefense reported a buffer overflow flaw in the ISO9660 filesystem
code. An attacker could create a malicious filesystem in such a way
that root privileges may be obtained if the filesystem is mounted. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2004-0109 to this issue.

All Red Hat Enterprise Linux 3 users are advised to upgrade their
kernels to the packages associated with their machine architectures
and configurations as listed in this erratum."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0109.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0424.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.isec.pl/vulnerabilities/isec-0015-msfilter.txt"
  );
  # http://www.idefense.com/application/poi/display?id=101
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42454434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2004-183.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-BOOT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem-unsupported");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp-unsupported");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-unsupported");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2004:183";
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
  if (rpm_check(release:"RHEL3", reference:"kernel-2.4.21-9.0.3.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"kernel-BOOT-2.4.21-9.0.3.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"kernel-doc-2.4.21-9.0.3.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i686", reference:"kernel-hugemem-2.4.21-9.0.3.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i686", reference:"kernel-hugemem-unsupported-2.4.21-9.0.3.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i686", reference:"kernel-smp-2.4.21-9.0.3.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"x86_64", reference:"kernel-smp-2.4.21-9.0.3.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i686", reference:"kernel-smp-unsupported-2.4.21-9.0.3.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"x86_64", reference:"kernel-smp-unsupported-2.4.21-9.0.3.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"kernel-source-2.4.21-9.0.3.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"kernel-unsupported-2.4.21-9.0.3.EL")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-BOOT / kernel-doc / kernel-hugemem / etc");
  }
}
