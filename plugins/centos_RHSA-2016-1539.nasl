#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1539 and 
# CentOS Errata and Security Advisory 2016:1539 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(92702);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2015-8660", "CVE-2016-2143", "CVE-2016-4470");
  script_osvdb_id(132260, 135975, 140046);
  script_xref(name:"RHSA", value:"2016:1539");

  script_name(english:"CentOS 7 : kernel (CESA-2016:1539)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

These updated kernel packages include several security issues and
numerous bug fixes, some of which you can see below. Space precludes
documenting all of these bug fixes in this advisory. To see the
complete list of bug fixes, users are directed to the related
Knowledge Article: https://access.redhat.com/articles/2460971.

Security Fix(es) :

* A flaw was found in the Linux kernel's keyring handling code, where
in key_reject_and_link() an uninitialised variable would eventually
lead to arbitrary free address which could allow attacker to use a
use-after-free style attack. (CVE-2016-4470, Important)

* The ovl_setattr function in fs/overlayfs/inode.c in the Linux kernel
through 4.3.3 attempts to merge distinct setattr operations, which
allows local users to bypass intended access restrictions and modify
the attributes of arbitrary overlay files via a crafted application.
(CVE-2015-8660, Moderate)

* It was reported that on s390x, the fork of a process with four page
table levels will cause memory corruption with a variety of symptoms.
All processes are created with three level page table and a limit of
4TB for the address space. If the parent process has four page table
levels with a limit of 8PB, the function that duplicates the address
space will try to copy memory areas outside of the address space limit
for the child process. (CVE-2016-2143, Moderate)

Red Hat would like to thank Nathan Williams for reporting
CVE-2015-8660. The CVE-2016-4470 issue was discovered by David Howells
(Red Hat Inc.).

Bug Fix(es) :

* The glibc headers and the Linux headers share certain definitions of
key structures that are required to be defined in kernel and in
userspace. In some instances both userspace and sanitized kernel
headers have to be included in order to get the structure definitions
required by the user program. Unfortunately because the glibc and
Linux headers don't coordinate this can result in compilation errors.
The glibc headers have therefore been fixed to coordinate with Linux
UAPI-based headers. With the header coordination compilation errors no
longer occur. (BZ#1331285)

* When running the TCP/IPv6 traffic over the mlx4_en networking
interface on the big endian architectures, call traces reporting about
a 'hw csum failure' could occur. With this update, the mlx4_en driver
has been fixed by correction of the checksum calculation for the big
endian architectures. As a result, the call trace error no longer
appears in the log messages. (BZ#1337431)

* Under significant load, some applications such as logshifter could
generate bursts of log messages too large for the system logger to
spool. Due to a race condition, log messages from that application
could then be lost even after the log volume dropped to manageable
levels. This update fixes the kernel mechanism used to notify the
transmitter end of the socket used by the system logger that more
space is available on the receiver side, removing a race condition
which previously caused the sender to stop transmitting new messages
and allowing all log messages to be processed correctly. (BZ#1337513)

* Previously, after heavy open or close of the Accelerator Function
Unit (AFU) contexts, the interrupt packet went out and the AFU context
did not see any interrupts. Consequently, a kernel panic could occur.
The provided patch set fixes handling of the interrupt requests, and
kernel panic no longer occurs in the described situation. (BZ#1338886)

* net: recvfrom would fail on short buffer. (BZ#1339115) * Backport
rhashtable changes from upstream. (BZ#1343639) * Server Crashing after
starting Glusterd & creating volumes. (BZ#1344234) * RAID5 reshape
deadlock fix. (BZ#1344313) * BDX perf uncore support fix. (BZ#1347374)"
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-August/022025.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bf4b94ba"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Overlayfs Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-devel-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-doc-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-headers-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perf-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-perf-3.10.0-327.28.2.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
