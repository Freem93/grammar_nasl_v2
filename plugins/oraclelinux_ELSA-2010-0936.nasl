#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0936 and 
# Oracle Linux Security Advisory ELSA-2010-0936 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68153);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 16:49:14 $");

  script_cve_id("CVE-2010-3432", "CVE-2010-3442");
  script_bugtraq_id(43480, 43787);
  script_osvdb_id(69424);
  script_xref(name:"RHSA", value:"2010:0936");

  script_name(english:"Oracle Linux 4 : kernel (ELSA-2010-0936)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0936 :

Updated kernel packages that fix two security issues and multiple bugs
are now available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

[Update 6 December 2010] The package list in this erratum has been
updated to include the kernel-doc packages for the IA32 architecture.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security fixes :

* A flaw in sctp_packet_config() in the Linux kernel's Stream Control
Transmission Protocol (SCTP) implementation could allow a remote
attacker to cause a denial of service. (CVE-2010-3432, Important)

* A missing integer overflow check in snd_ctl_new() in the Linux
kernel's sound subsystem could allow a local, unprivileged user on a
32-bit system to cause a denial of service or escalate their
privileges. (CVE-2010-3442, Important)

Red Hat would like to thank Dan Rosenberg for reporting CVE-2010-3442.

Bug fixes :

* Forward time drift was observed on virtual machines using PM
timer-based kernel tick accounting and running on KVM or the Microsoft
Hyper-V Server hypervisor. Virtual machines that were booted with the
divider=x kernel parameter set to a value greater than 1 and that
showed the following in the kernel boot messages were subject to this
issue :

time.c: Using PM based timekeeping

Fine grained accounting for the PM timer is introduced which
eliminates this issue. However, this fix uncovered a bug in the Xen
hypervisor, possibly causing backward time drift. If this erratum is
installed in Xen HVM guests that meet the aforementioned conditions,
it is recommended that the host use kernel-xen-2.6.18-194.26.1.el5 or
newer, which includes a fix (BZ#641915) for the backward time drift.
(BZ#629237)

* With multipath enabled, systems would occasionally halt when the
do_cciss_request function was used. This was caused by
wrongly-generated requests. Additional checks have been added to avoid
the aforementioned issue. (BZ#640193)

* A Sun X4200 system equipped with a QLogic HBA spontaneously rebooted
and logged a Hyper-Transport Sync Flood Error to the system event log.
A Maximum Memory Read Byte Count restriction was added to fix this
bug. (BZ#640919)

* For an active/backup bonding network interface with VLANs on top of
it, when a link failed over, it took a minute for the multicast domain
to be rejoined. This was caused by the driver not sending any IGMP
join packets. The driver now sends IGMP join packets and the multicast
domain is rejoined immediately. (BZ#641002)

* Replacing a disk and trying to rebuild it afterwards caused the
system to panic. When a domain validation request for a hot plugged
drive was sent, the mptscsi driver did not validate its existence.
This could result in the driver accessing random memory and causing
the crash. A check has been added that describes the newly-added
device and reloads the iocPg3 data from the firmware if needed.
(BZ#641137)

* An attempt to create a VLAN interface on a bond of two bnx2 adapters
in two switch configurations resulted in a soft lockup after a few
seconds. This was caused by an incorrect use of a bonding pointer.
With this update, soft lockups no longer occur and creating a VLAN
interface works as expected. (BZ#641254)

* Erroneous pointer checks could have caused a kernel panic. This was
due to a critical value not being copied when a network buffer was
duplicated and consumed by multiple portions of the kernel's network
stack. Fixing the copy operation resolved this bug. (BZ#642746)

* A typo in a variable name caused it to be dereferenced in either
mkdir() or create() which could cause a kernel panic. (BZ#643342)

* SCSI high level drivers can submit SCSI commands which would never
be completed when the device was offline. This was caused by a missing
callback for the request to complete the given command. SCSI requests
are now terminated by calling their callback when a device is offline.
(BZ#644816)

* A kernel panic could have occurred on systems due to a recursive
lock in the 3c59x driver. Recursion is now avoided and this kernel
panic no longer occurs. (BZ#648407)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-December/001754.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-largesmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-largesmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xenU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xenU-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_exists(release:"EL4", rpm:"kernel-2.6.9") && rpm_check(release:"EL4", reference:"kernel-2.6.9-89.33.1.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-devel-2.6.9") && rpm_check(release:"EL4", reference:"kernel-devel-2.6.9-89.33.1.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-doc-2.6.9") && rpm_check(release:"EL4", cpu:"ia64", reference:"kernel-doc-2.6.9-89.33.1.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-doc-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-doc-2.6.9-89.33.1.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-hugemem-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-89.33.1.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-hugemem-devel-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-89.33.1.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-largesmp-2.6.9") && rpm_check(release:"EL4", cpu:"ia64", reference:"kernel-largesmp-2.6.9-89.33.1.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-largesmp-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-89.33.1.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-largesmp-devel-2.6.9") && rpm_check(release:"EL4", cpu:"ia64", reference:"kernel-largesmp-devel-2.6.9-89.33.1.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-largesmp-devel-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-89.33.1.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-smp-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-smp-2.6.9-89.33.1.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-smp-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-smp-2.6.9-89.33.1.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-smp-devel-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-smp-devel-2.6.9-89.33.1.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-smp-devel-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-89.33.1.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-xenU-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-xenU-2.6.9-89.33.1.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-xenU-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-xenU-2.6.9-89.33.1.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-xenU-devel-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-xenU-devel-2.6.9-89.33.1.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-xenU-devel-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-xenU-devel-2.6.9-89.33.1.0.1.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
