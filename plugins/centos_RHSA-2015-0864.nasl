#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0864 and 
# CentOS Errata and Security Advisory 2015:0864 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(82999);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/26 15:53:26 $");

  script_cve_id("CVE-2014-3215", "CVE-2014-3690", "CVE-2014-7825", "CVE-2014-7826", "CVE-2014-8171", "CVE-2014-8884", "CVE-2014-9529", "CVE-2014-9584", "CVE-2015-1421");
  script_bugtraq_id(67341, 70691, 70971, 70972, 71097, 71880, 71883, 72356, 74293);
  script_osvdb_id(113629, 114369, 114370, 114957, 116762, 116767, 117716, 121104);
  script_xref(name:"RHSA", value:"2015:0864");

  script_name(english:"CentOS 6 : kernel (CESA-2015:0864)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* A flaw was found in the way seunshare, a utility for running
executables under a different security context, used the capng_lock
functionality of the libcap-ng library. The subsequent invocation of
suid root binaries that relied on the fact that the setuid() system
call, among others, also sets the saved set-user-ID when dropping the
binaries' process privileges, could allow a local, unprivileged user
to potentially escalate their privileges on the system. Note: the fix
for this issue is the kernel part of the overall fix, and introduces
the PR_SET_NO_NEW_PRIVS functionality and the related SELinux exec
transitions support. (CVE-2014-3215, Important)

* A use-after-free flaw was found in the way the Linux kernel's SCTP
implementation handled authentication key reference counting during
INIT collisions. A remote attacker could use this flaw to crash the
system or, potentially, escalate their privileges on the system.
(CVE-2015-1421, Important)

* It was found that the Linux kernel's KVM implementation did not
ensure that the host CR4 control register value remained unchanged
across VM entries on the same virtual CPU. A local, unprivileged user
could use this flaw to cause a denial of service on the system.
(CVE-2014-3690, Moderate)

* An out-of-bounds memory access flaw was found in the syscall tracing
functionality of the Linux kernel's perf subsystem. A local,
unprivileged user could use this flaw to crash the system.
(CVE-2014-7825, Moderate)

* An out-of-bounds memory access flaw was found in the syscall tracing
functionality of the Linux kernel's ftrace subsystem. On a system with
ftrace syscall tracing enabled, a local, unprivileged user could use
this flaw to crash the system, or escalate their privileges.
(CVE-2014-7826, Moderate)

* It was found that the Linux kernel memory resource controller's
(memcg) handling of OOM (out of memory) conditions could lead to
deadlocks. An attacker able to continuously spawn new processes within
a single memory-constrained cgroup during an OOM event could use this
flaw to lock up the system. (CVE-2014-8171, Moderate)

* A race condition flaw was found in the way the Linux kernel keys
management subsystem performed key garbage collection. A local
attacker could attempt accessing a key while it was being garbage
collected, which would cause the system to crash. (CVE-2014-9529,
Moderate)

* A stack-based buffer overflow flaw was found in the
TechnoTrend/Hauppauge DEC USB device driver. A local user with write
access to the corresponding device could use this flaw to crash the
kernel or, potentially, elevate their privileges on the system.
(CVE-2014-8884, Low)

* An information leak flaw was found in the way the Linux kernel's
ISO9660 file system implementation accessed data on an ISO9660 image
with RockRidge Extension Reference (ER) records. An attacker with
physical access to the system could use this flaw to disclose up to
255 bytes of kernel memory. (CVE-2014-9584, Low)

Red Hat would like to thank Andy Lutomirski for reporting
CVE-2014-3215 and CVE-2014-3690, Robert Swiecki for reporting
CVE-2014-7825 and CVE-2014-7826, and Carl Henrik Lunde for reporting
CVE-2014-9584. The CVE-2015-1421 issue was discovered by Sun Baoliang
of Red Hat.

This update also fixes several bugs. Documentation for these changes
is available from the Technical Notes document linked to in the
References section.

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The system
must be rebooted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-April/021083.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?25dcfb86"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"kernel-2.6.32-504.16.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-abi-whitelists-2.6.32-504.16.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-2.6.32-504.16.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-devel-2.6.32-504.16.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-devel-2.6.32-504.16.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-doc-2.6.32-504.16.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-firmware-2.6.32-504.16.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-headers-2.6.32-504.16.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"perf-2.6.32-504.16.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-perf-2.6.32-504.16.2.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
