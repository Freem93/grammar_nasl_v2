#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:689. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16054);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/05/22 13:36:33 $");

  script_cve_id("CVE-2004-0565", "CVE-2004-1016", "CVE-2004-1017", "CVE-2004-1137", "CVE-2004-1144", "CVE-2004-1234", "CVE-2004-1335");
  script_osvdb_id(7585, 12386, 12387, 12388, 12527, 12589, 12590);
  script_xref(name:"RHSA", value:"2004:689");

  script_name(english:"RHEL 3 : kernel (RHSA-2004:689)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix several security issues in Red Hat
Enterprise Linux 3 are now available.

The Linux kernel handles the basic functions of the operating system.

This advisory includes fixes for several security issues :

Petr Vandrovec discovered a flaw in the 32bit emulation code affecting
the Linux 2.4 kernel on the AMD64 architecture. A local attacker could
use this flaw to gain privileges. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2004-1144
to this issue.

ISEC security research discovered multiple vulnerabilities in the IGMP
functionality which was backported in the Red Hat Enterprise Linux 3
kernels. These flaws could allow a local user to cause a denial of
service (crash) or potentially gain privileges. Where multicast
applications are being used on a system, these flaws may also allow
remote users to cause a denial of service. The Common Vulnerabilities
and Exposures project (cve.mitre.org) has assigned the name
CVE-2004-1137 to this issue.

ISEC security research and Georgi Guninski independently discovered a
flaw in the scm_send function in the auxiliary message layer. A local
user could create a carefully crafted auxiliary message which could
cause a denial of service (system hang). The Common Vulnerabilities
and Exposures project (cve.mitre.org) has assigned the name
CVE-2004-1016 to this issue.

A floating point information leak was discovered in the ia64
architecture context switch code. A local user could use this flaw to
read register values of other processes by setting the MFH bit. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2004-0565 to this issue.

Kirill Korotaev found a flaw in load_elf_binary affecting kernels
prior to 2.4.26. A local user could create a carefully crafted binary
in such a way that it would cause a denial of service (system crash).
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2004-1234 to this issue.

These packages also fix issues in the io_edgeport driver, and a memory
leak in ip_options_get.

Note: The kernel-unsupported package contains various drivers and
modules that are unsupported and therefore might contain security
problems that have not been addressed.

All Red Hat Enterprise Linux 3 users are advised to upgrade their
kernels to the packages associated with their machine architectures
and configurations as listed in this erratum."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0565.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1017.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1137.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1144.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1234.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1335.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2004-689.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/05/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2004:689";
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
  if (rpm_check(release:"RHEL3", reference:"kernel-2.4.21-27.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"kernel-BOOT-2.4.21-27.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"kernel-doc-2.4.21-27.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i686", reference:"kernel-hugemem-2.4.21-27.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i686", reference:"kernel-hugemem-unsupported-2.4.21-27.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i686", reference:"kernel-smp-2.4.21-27.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"x86_64", reference:"kernel-smp-2.4.21-27.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i686", reference:"kernel-smp-unsupported-2.4.21-27.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"x86_64", reference:"kernel-smp-unsupported-2.4.21-27.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"kernel-source-2.4.21-27.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"kernel-unsupported-2.4.21-27.0.1.EL")) flag++;

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
