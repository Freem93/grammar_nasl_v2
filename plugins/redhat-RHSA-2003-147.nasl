#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2003:147. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12390);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/28 17:44:43 $");

  script_cve_id("CVE-2003-0244", "CVE-2003-0246");
  script_xref(name:"RHSA", value:"2003:147");

  script_name(english:"RHEL 2.1 : kernel (RHSA-2003:147)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"These updated kernel packages address security vulnerabilites,
including two possible data corruption scenarios. In addition, a
number of drivers have been updated, improvements made to system
performance, and various issues have been resolved.

The Linux kernel handles the basic functions of the operating system.

Two potential data corruption scenarios have been identified. These
scenarios can occur under heavy, complex I/O loads.

The first scenario only occurs while performing memory mapped file
I/O, where the file is simultaneously unlinked and the corresponding
file blocks reallocated. Furthermore, the memory mapped must be to a
partial page at the end of a file on an ext3 file system. As such, Red
Hat considers this scenario unlikely.

The second scenario was exhibited in systems with more than 4 GB of
memory with a storage controller capable of block device DMA above 4GB
(64-bit DMA). By restricting storage drivers to 32-bit DMA, the
problem was resolved. Prior to this errata, the SCSI subsystem was
already restricted to 32-bit DMA; this errata extends the restriction
to block drivers as well. The change consists of disabling 64-bit DMA
in the cciss driver (the HP SA5xxx and SA6xxx RAID controllers). The
performance implications of this change to the cciss driver are
minimal.

In addition, the following security vulnerabilities have been
addressed :

A flaw was found in several hash table implementations in the kernel
networking code. A remote attacker sending packets with carefully
chosen, forged source addresses could potentially cause every routing
cache entry to be hashed into the same hash chain. As a result, the
kernel would use a disproportionate amount of processor time to deal
with the new packets, leading to a remote denial-of-service (DoS)
attack. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2003-0244 to this issue.

A flaw was also found in the 'ioperm' system call, which fails to
properly restrict privileges. This flaw can allow an unprivileged
local user to gain read and write access to I/O ports on the system.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2003-0246 to this issue.

In addition, the following drivers have been updated to the versions
indicated :

-aacraid: 0.9.9ac6-TEST -qlogic qla2100, qla2200, qla2300: 6.04.01
-aic7xxx_mod: 6.2.30 and aic79xx: 1.3.4 -ips: v6.00.26 -cpqfc: 2.1.2
-fusion: 2.05.00 -e100: 2.2.21-k1 -e1000: 5.0.43-k1, and added netdump
support -natsemi: 1.07+LK1.0.17 -cciss: 2.4.45. -cpqarray: 2.4.26

If the system is configured to use alternate drivers, we recommend
applying the kudzu errata RHEA-2003:132 prior to updating the kernel.

A number of edge conditions in the virtual memory system have been
identified and resolved. These included the elimination of memory
allocation failures occuring when the system had not depleted all of
the physical memory. This would typically lead to process creation and
network driver failures, and general performance degradation.
Additional memory reclamation improvements were introduced to further
smooth out the natural system performance degradation that occur under
memory exhaustion conditions.

In addition, the latest summit patches have been included.

All users should upgrade to these errata packages, which address these
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0244.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0246.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2003-147.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-BOOT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-enterprise");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-summit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/05/29");
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
if (! ereg(pattern:"^2\.1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2003:147";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i686", reference:"kernel-2.4.9-e.24")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kernel-BOOT-2.4.9-e.24")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i686", reference:"kernel-debug-2.4.9-e.24")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kernel-doc-2.4.9-e.24")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i686", reference:"kernel-enterprise-2.4.9-e.24")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kernel-headers-2.4.9-e.24")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i686", reference:"kernel-smp-2.4.9-e.24")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kernel-source-2.4.9-e.24")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i686", reference:"kernel-summit-2.4.9-e.24")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-BOOT / kernel-debug / kernel-doc / etc");
  }
}
