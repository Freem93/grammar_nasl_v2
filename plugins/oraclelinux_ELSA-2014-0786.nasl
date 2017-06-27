#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:0786 and 
# Oracle Linux Security Advisory ELSA-2014-0786 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(76738);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/04/10 13:19:30 $");

  script_cve_id("CVE-2014-0206", "CVE-2014-1737", "CVE-2014-1738", "CVE-2014-2568", "CVE-2014-2851", "CVE-2014-3144", "CVE-2014-3145", "CVE-2014-3153");
  script_bugtraq_id(66348, 66779, 67300, 67302, 67309, 67321, 67906, 68176);
  script_osvdb_id(108392);
  script_xref(name:"RHSA", value:"2014:0786");

  script_name(english:"Oracle Linux 7 : kernel (ELSA-2014-0786)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2014:0786 :

Updated kernel packages that fix multiple security issues, several
bugs, and add various enhancements are now available for Red Hat
Enterprise Linux 7.

The Red Hat Security Response Team has rated this update as having
Important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* A flaw was found in the way the Linux kernel's futex subsystem
handled the requeuing of certain Priority Inheritance (PI) futexes. A
local, unprivileged user could use this flaw to escalate their
privileges on the system. (CVE-2014-3153, Important)

* A use-after-free flaw was found in the way the ping_init_sock()
function of the Linux kernel handled the group_info reference counter.
A local, unprivileged user could use this flaw to crash the system or,
potentially, escalate their privileges on the system. (CVE-2014-2851,
Important)

* Use-after-free and information leak flaws were found in the way the
Linux kernel's floppy driver processed the FDRAWCMD IOCTL command. A
local user with write access to /dev/fdX could use these flaws to
escalate their privileges on the system. (CVE-2014-1737,
CVE-2014-1738, Important)

* It was found that the aio_read_events_ring() function of the Linux
kernel's Asynchronous I/O (AIO) subsystem did not properly sanitize
the AIO ring head received from user space. A local, unprivileged user
could use this flaw to disclose random parts of the (physical) memory
belonging to the kernel and/or other processes. (CVE-2014-0206,
Moderate)

* An out-of-bounds memory access flaw was found in the Netlink
Attribute extension of the Berkeley Packet Filter (BPF) interpreter
functionality in the Linux kernel's networking implementation. A
local, unprivileged user could use this flaw to crash the system or
leak kernel memory to user space via a specially crafted socket
filter. (CVE-2014-3144, CVE-2014-3145, Moderate)

* An information leak flaw was found in the way the skb_zerocopy()
function copied socket buffers (skb) that are backed by user-space
buffers (for example vhost-net and Xen netback), potentially allowing
an attacker to read data from those buffers. (CVE-2014-2568, Low)

Red Hat would like to thank Kees Cook of Google for reporting
CVE-2014-3153 and Matthew Daley for reporting CVE-2014-1737 and
CVE-2014-1738. Google acknowledges Pinkie Pie as the original reporter
of CVE-2014-3153. The CVE-2014-0206 issue was discovered by Mateusz
Guzik of Red Hat.

This update also fixes the following bugs :

* Due to incorrect calculation of Tx statistics in the qlcninc driver,
running the 'ethtool -S ethX' command could trigger memory corruption.
As a consequence, running the sosreport tool, that uses this command,
resulted in a kernel panic. The problem has been fixed by correcting
the said statistics calculation. (BZ#1104972)

* When an attempt to create a file on the GFS2 file system failed due
to a file system quota violation, the relevant VFS inode was not
completely uninitialized. This could result in a list corruption
error. This update resolves this problem by correctly uninitializing
the VFS inode in this situation. (BZ#1097407)

* Due to a race condition in the kernel, the getcwd() system call
could return '/' instead of the correct full path name when querying a
path name of a file or directory. Paths returned in the '/proc' file
system could also be incorrect. This problem was causing instability
of various applications. The aforementioned race condition has been
fixed and getcwd() now always returns the correct paths. (BZ#1099048)

In addition, this update adds the following enhancements :

* The kernel mutex code has been improved. The changes include
improved queuing of the MCS spin locks, the MCS code optimization,
introduction of the cancellable MCS spin locks, and improved handling
of mutexes without wait locks. (BZ#1103631, BZ#1103629)

* The handling of the Virtual Memory Area (VMA) cache and huge page
faults has been improved. (BZ#1103630)

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add these
enhancements. The system must be rebooted for this update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-July/004282.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Android \'Towelroot\' Futex Requeue Kernel Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_exists(release:"EL7", rpm:"kernel-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-3.10.0-123.4.2.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-abi-whitelists-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-123.4.2.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-debug-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-debug-3.10.0-123.4.2.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-debug-devel-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-123.4.2.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-devel-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-devel-3.10.0-123.4.2.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-doc-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-doc-3.10.0-123.4.2.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-headers-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-headers-3.10.0-123.4.2.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-tools-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-tools-3.10.0-123.4.2.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-tools-libs-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-123.4.2.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-tools-libs-devel-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-123.4.2.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"perf-3.10.0-123.4.2.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python-perf-3.10.0-123.4.2.el7")) flag++;


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
