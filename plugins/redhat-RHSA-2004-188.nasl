#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:188. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12494);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/12/28 17:44:44 $");

  script_cve_id("CVE-2003-0461", "CVE-2003-0465", "CVE-2003-0984", "CVE-2003-1040", "CVE-2004-0003", "CVE-2004-0010");
  script_xref(name:"RHSA", value:"2004:188");

  script_name(english:"RHEL 3 : kernel (RHSA-2004:188)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages are now available as part of ongoing support
and maintenance of Red Hat Enterprise Linux version 3. This is the
second regular update.

The Linux kernel handles the basic functions of the operating system.

This is the second regular kernel update to Red Hat Enterprise Linux
version 3. It contains several minor security fixes, many bug fixes,
device driver updates, new hardware support, and the introduction of
Linux Syscall Auditing support.

There were bug fixes in many different parts of the kernel, the bulk
of which addressed unusual situations such as error handling, race
conditions, and resource starvation. The combined effect of the
approximately 140 fixes is a strong improvement in the reliability and
durability of Red Hat Enterprise Linux. Some of the key areas affected
are disk drivers, network drivers, USB support, x86_64 and ppc64
platform support, ia64 32-bit emulation layer enablers, and the VM,
NFS, IPv6, and SCSI subsystems.

A significant change in the SCSI subsystem (the disabling of the
scsi-affine-queue patch) should significantly improve SCSI disk driver
performance in many scenarios. There were 10 Bugzillas against SCSI
performance problems addressed by this change.

The following drivers have been upgraded to new versions :

bonding ---- 2.4.1 cciss ------ 2.4.50.RH1 e1000 ------ 5.2.30.1-k1
fusion ----- 2.05.11.03 ipr -------- 1.0.3 ips -------- 6.11.07
megaraid2 -- 2.10.1.1 qla2x00 ---- 6.07.02-RH1 tg3 -------- 3.1
z90crypt --- 1.1.4

This update introduces support for the new Intel EM64T processor. A
new 'ia32e' architecture has been created to support booting on
platforms based on either the original AMD Opteron CPU or the new
Intel EM64T CPU. The existing 'x86_64' architecture has remained
optimized for Opteron systems. Kernels for both types of systems are
built from the same x86_64-architecture sources and share a common
kernel source RPM (kernel-source-2.4.21-15.EL.x86_64.rpm).

Other highlights in this update include a major upgrade to the SATA
infrastructure, addition of IBM JS20 Power Blade support, and creation
of an optional IBM eServer zSeries On-Demand Timer facility for
reducing idle CPU overhead.

The following security issues were addressed in this update :

A minor flaw was found where /proc/tty/driver/serial reveals the exact
character counts for serial links. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2003-0461
to this issue.

The kernel strncpy() function in Linux 2.4 and 2.5 does not pad the
target buffer with null bytes on architectures other than x86, as
opposed to the expected libc behavior, which could lead to information
leaks. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2003-0465 to this issue.

A minor data leak was found in two real time clock drivers (for
/dev/rtc). The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2003-0984 to this issue.

A flaw in the R128 Direct Render Infrastructure (dri) driver could
allow local privilege escalation. This driver is part of the
kernel-unsupported package. The Common Vulnera- bilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2004-0003 to this
issue.

A flaw in ncp_lookup() in ncpfs could allow local privilege
escalation. The ncpfs module allows a system to mount volumes of
NetWare servers or print to NetWare printers and is in the
kernel-unsupported package. The Common Vulnera- bilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2004-0010 to this
issue.

(Note that the kernel-unsupported package contains drivers and other
modules that are unsupported and therefore might contain security
problems that have not been addressed.)

All Red Hat Enterprise Linux 3 users are advised to upgrade their
kernels to the packages associated with their machine architectures
and configurations as listed in this erratum."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0461.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0465.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0984.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-1040.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2004-188.html"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2004/05/11");
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
  rhsa = "RHSA-2004:188";
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
  if (rpm_check(release:"RHEL3", reference:"kernel-2.4.21-15.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"kernel-BOOT-2.4.21-15.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"kernel-doc-2.4.21-15.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i686", reference:"kernel-hugemem-2.4.21-15.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i686", reference:"kernel-hugemem-unsupported-2.4.21-15.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i686", reference:"kernel-smp-2.4.21-15.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"x86_64", reference:"kernel-smp-2.4.21-15.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i686", reference:"kernel-smp-unsupported-2.4.21-15.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"x86_64", reference:"kernel-smp-unsupported-2.4.21-15.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"kernel-source-2.4.21-15.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"kernel-unsupported-2.4.21-15.EL")) flag++;

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
