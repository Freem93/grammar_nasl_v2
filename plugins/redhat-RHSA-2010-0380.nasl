#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0380. The text 
# itself is copyright (C) Red Hat, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63932);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/01/10 18:05:23 $");

  script_cve_id("CVE-2009-4027", "CVE-2009-4307", "CVE-2010-0727", "CVE-2010-1188");
  script_bugtraq_id(37170, 39016, 39101);
  script_xref(name:"RHSA", value:"2010:0380");

  script_name(english:"RHEL 5 : kernel (RHSA-2010:0380)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 5.4 Extended
Update Support.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security fixes :

* a race condition was found in the mac80211 implementation, a
framework used for writing drivers for wireless devices. An attacker
could trigger this flaw by sending a Delete Block ACK (DELBA) packet
to a target system, resulting in a remote denial of service. Note:
This issue only affected users on 802.11n networks, and that also use
the iwlagn driver with Intel wireless hardware. (CVE-2009-4027,
Important)

* a use-after-free flaw was found in the tcp_rcv_state_process()
function in the Linux kernel TCP/IP protocol suite implementation. If
a system using IPv6 had the IPV6_RECVPKTINFO option set on a listening
socket, a remote attacker could send an IPv6 packet to that system,
causing a kernel panic (denial of service). (CVE-2010-1188, Important)

* a flaw was found in the gfs2_lock() implementation. The GFS2 locking
code could skip the lock operation for files that have the S_ISGID bit
(set-group-ID on execution) in their mode set. A local, unprivileged
user on a system that has a GFS2 file system mounted could use this
flaw to cause a kernel panic (denial of service). (CVE-2010-0727,
Moderate)

* a divide-by-zero flaw was found in the ext4 file system code. A
local attacker could use this flaw to cause a denial of service by
mounting a specially crafted ext4 file system. (CVE-2009-4307, Low)

Bug fixes :

* if a program that calls posix_fadvise() were compiled on x86, and
then run on a 64-bit system, that program could experience various
problems, including performance issues and the call to posix_fadvise()
failing, causing the program to not run as expected or even abort.
With this update, when such programs attempt to call posix_fadvise()
on 64-bit systems, sys32_fadvise64() is called instead, which resolves
this issue. This update also fixes other 32-bit system calls that were
mistakenly called on 64-bit systems (including systems running the
kernel-xen kernel). (BZ#569597)

* on some systems able to set a P-State limit via the BIOS, it was not
possible to set the limit to a higher frequency if the system was
rebooted while a low limit was set:
'/sys/devices/system/cpu/cpu[x]/cpufreq/scaling_max_freq' would retain
the low limit in these situations. With this update, limits are
correctly set, even after being changed after a system reboot.
(BZ#569727)

* certain Intel ICH hardware (using the e1000e driver) has an NFS
filtering capability that did not work as expected, causing memory
corruption, which could lead to kernel panics, or other unexpected
behavior. In a reported case, a panic occurred when running NFS
connection tests. This update resolves this issue by disabling the
filtering capability. (BZ#569797)

* if 'open(/proc/[PID]/[xxxx])' was called at the same time the
process was exiting, the call would fail with an EINVAL error (an
incorrect error for this situation). With this update, the correct
error, ENOENT, is returned in this situation. (BZ#571362)

* multiqueue is used for transmitting data, but a single queue
transmit ON/OFF scheme was used. This led to a race condition on
systems with the bnx2x driver in situations where one queue became
full, but not stopped, and the other queue enabled transmission. With
this update, only a single queue is used. (BZ#576951)

* the '/proc/sys/vm/mmap_min_addr' tunable helps prevent unprivileged
users from creating new memory mappings below the minimum address. The
sysctl value for mmap_min_addr could be changed by a process or user
that has an effective user ID (euid) of 0, even if the process or user
does not have the CAP_SYS_RAWIO capability. This update adds a
capability check for the CAP_SYS_RAWIO capability before allowing the
mmap_min_addr value to be changed. (BZ#577206)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-4027.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-4307.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-0727.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1188.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0380.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-2.6.18-164.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-2.6.18-164.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-2.6.18-164.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-PAE-2.6.18-164.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-PAE-devel-2.6.18-164.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-debug-2.6.18-164.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-debug-2.6.18-164.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-debug-2.6.18-164.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-debug-devel-2.6.18-164.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-debug-devel-2.6.18-164.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-debug-devel-2.6.18-164.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-devel-2.6.18-164.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-devel-2.6.18-164.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-devel-2.6.18-164.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", reference:"kernel-doc-2.6.18-164.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i386", reference:"kernel-headers-2.6.18-164.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-headers-2.6.18-164.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-headers-2.6.18-164.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-kdump-2.6.18-164.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-kdump-devel-2.6.18-164.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-xen-2.6.18-164.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-xen-2.6.18-164.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-xen-devel-2.6.18-164.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-xen-devel-2.6.18-164.17.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
