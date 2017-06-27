#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0474 and 
# Oracle Linux Security Advisory ELSA-2010-0474 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68049);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/06 16:53:47 $");

  script_cve_id("CVE-2009-3726", "CVE-2010-1173", "CVE-2010-1437");
  script_bugtraq_id(36936, 39719, 39794);
  script_osvdb_id(59877);
  script_xref(name:"RHSA", value:"2010:0474");

  script_name(english:"Oracle Linux 4 : kernel (ELSA-2010-0474)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0474 :

Updated kernel packages that fix three security issues and several
bugs are now available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security fixes :

* a NULL pointer dereference flaw was found in the Linux kernel NFSv4
implementation. Several of the NFSv4 file locking functions failed to
check whether a file had been opened on the server before performing
locking operations on it. A local, unprivileged user on a system with
an NFSv4 share mounted could possibly use this flaw to cause a kernel
panic (denial of service) or escalate their privileges.
(CVE-2009-3726, Important)

* a flaw was found in the sctp_process_unk_param() function in the
Linux kernel Stream Control Transmission Protocol (SCTP)
implementation. A remote attacker could send a specially crafted SCTP
packet to an SCTP listening port on a target system, causing a kernel
panic (denial of service). (CVE-2010-1173, Important)

* a race condition between finding a keyring by name and destroying a
freed keyring was found in the Linux kernel key management facility. A
local, unprivileged user could use this flaw to cause a kernel panic
(denial of service) or escalate their privileges. (CVE-2010-1437,
Important)

Red Hat would like to thank Simon Vallet for responsibly reporting
CVE-2009-3726; and Jukka Taimisto and Olli Jarva of Codenomicon Ltd,
Nokia Siemens Networks, and Wind River on behalf of their customer,
for responsibly reporting CVE-2010-1173.

Bug fixes :

* RHBA-2007:0791 introduced a regression in the Journaling Block
Device (JBD). Under certain circumstances, removing a large file (such
as 300 MB or more) did not result in inactive memory being freed,
leading to the system having a large amount of inactive memory. Now,
the memory is correctly freed. (BZ#589155)

* the timer_interrupt() routine did not scale lost real ticks to
logical ticks correctly, possibly causing time drift for 64-bit Red
Hat Enterprise Linux 4 KVM (Kernel-based Virtual Machine) guests that
were booted with the 'divider=x' kernel parameter set to a value
greater than 1. 'warning: many lost ticks' messages may have been
logged on the affected guest systems. (BZ#590551)

* a bug could have prevented NFSv3 clients from having the most
up-to-date file attributes for files on a given NFSv3 file system. In
cases where a file type changed, such as if a file was removed and
replaced with a directory of the same name, the NFSv3 client may not
have noticed this change until stat(2) was called (for example, by
running 'ls -l'). (BZ#596372)

* RHBA-2007:0791 introduced bugs in the Linux kernel PCI-X subsystem.
These could have caused a system deadlock on some systems where the
BIOS set the default Maximum Memory Read Byte Count (MMRBC) to 4096,
and that also use the Intel PRO/1000 Linux driver, e1000. Errors such
as 'e1000: eth[x]: e1000_clean_tx_irq: Detected Tx Unit Hang' were
logged. (BZ#596374)

* an out of memory condition in a KVM guest, using the virtio-net
network driver and also under heavy network stress, could have
resulted in that guest being unable to receive network traffic. Users
had to manually remove and re-add the virtio_net module and restart
the network service before networking worked as expected. Such memory
conditions no longer prevent KVM guests receiving network traffic.
(BZ#597310)

* when an SFQ qdisc that limited the queue size to two packets was
added to a network interface, sending traffic through that interface
resulted in a kernel crash. Such a qdisc no longer results in a kernel
crash. (BZ#597312)

* when an NFS client opened a file with the O_TRUNC flag set, it
received a valid stateid, but did not use that stateid to perform the
SETATTR call. Such cases were rejected by Red Hat Enterprise Linux 4
NFS servers with an 'NFS4ERR_BAD_STATEID' error, possibly preventing
some NFS clients from writing files to an NFS file system. (BZ#597314)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-June/001499.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_exists(release:"EL4", rpm:"kernel-2.6.9") && rpm_check(release:"EL4", reference:"kernel-2.6.9-89.0.26.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-devel-2.6.9") && rpm_check(release:"EL4", reference:"kernel-devel-2.6.9-89.0.26.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-doc-2.6.9") && rpm_check(release:"EL4", reference:"kernel-doc-2.6.9-89.0.26.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-hugemem-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-89.0.26.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-hugemem-devel-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-89.0.26.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-largesmp-2.6.9") && rpm_check(release:"EL4", cpu:"ia64", reference:"kernel-largesmp-2.6.9-89.0.26.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-largesmp-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-89.0.26.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-largesmp-devel-2.6.9") && rpm_check(release:"EL4", cpu:"ia64", reference:"kernel-largesmp-devel-2.6.9-89.0.26.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-largesmp-devel-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-89.0.26.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-smp-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-smp-2.6.9-89.0.26.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-smp-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-smp-2.6.9-89.0.26.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-smp-devel-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-smp-devel-2.6.9-89.0.26.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-smp-devel-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-89.0.26.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-xenU-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-xenU-2.6.9-89.0.26.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-xenU-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-xenU-2.6.9-89.0.26.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-xenU-devel-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-xenU-devel-2.6.9-89.0.26.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-xenU-devel-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-xenU-devel-2.6.9-89.0.26.0.1.EL")) flag++;


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
