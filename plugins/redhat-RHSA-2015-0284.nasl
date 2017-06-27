#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0284. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81624);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/06 15:51:01 $");

  script_cve_id("CVE-2013-4483", "CVE-2014-3185", "CVE-2014-3611", "CVE-2014-3645", "CVE-2014-3646", "CVE-2014-7841", "CVE-2014-8160");
  script_osvdb_id(99161, 110732, 113731, 114575, 117131);
  script_xref(name:"RHSA", value:"2015:0284");

  script_name(english:"RHEL 6 : kernel (RHSA-2015:0284)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 6.5 Extended
Update Support.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* A race condition flaw was found in the way the Linux kernel's KVM
subsystem handled PIT (Programmable Interval Timer) emulation. A guest
user who has access to the PIT I/O ports could use this flaw to crash
the host. (CVE-2014-3611, Important)

* A flaw was found in the way the Linux kernel's SCTP implementation
validated INIT chunks when performing Address Configuration Change
(ASCONF). A remote attacker could use this flaw to crash the system by
sending a specially crafted SCTP packet to trigger a NULL pointer
dereference on the system. (CVE-2014-7841, Important)

* A flaw was found in the way the ipc_rcu_putref() function in the
Linux kernel's IPC implementation handled reference counter
decrementing. A local, unprivileged user could use this flaw to
trigger an Out of Memory (OOM) condition and, potentially, crash the
system. (CVE-2013-4483, Moderate)

* A memory corruption flaw was found in the way the USB ConnectTech
WhiteHEAT serial driver processed completion commands sent via USB
Request Blocks buffers. An attacker with physical access to the system
could use this flaw to crash the system or, potentially, escalate
their privileges on the system. (CVE-2014-3185, Moderate)

* It was found that the Linux kernel's KVM subsystem did not handle
the VM exits gracefully for the invept (Invalidate Translations
Derived from EPT) and invvpid (Invalidate Translations Based on VPID)
instructions. On hosts with an Intel processor and invept/invppid VM
exit support, an unprivileged guest user could use these instructions
to crash the guest. (CVE-2014-3645, CVE-2014-3646, Moderate)

* A flaw was found in the way the Linux kernel's netfilter subsystem
handled generic protocol tracking. As demonstrated in the Stream
Control Transmission Protocol (SCTP) case, a remote attacker could use
this flaw to bypass intended iptables rule restrictions when the
associated connection tracking module was not loaded on the system.
(CVE-2014-8160, Moderate)

Red Hat would like to thank Lars Bull of Google for reporting
CVE-2014-3611, Vladimir Davydov (Parallels) for reporting
CVE-2013-4483, and the Advanced Threat Research team at Intel Security
for reporting CVE-2014-3645 and CVE-2014-3646. The CVE-2014-7841 issue
was discovered by Liu Wei of Red Hat.

Bug fixes :

* When forwarding a packet, the iptables target TCPOPTSTRIP used the
tcp_hdr() function to locate the option space. Consequently,
TCPOPTSTRIP located the incorrect place in the packet, and therefore
did not match options for stripping. TCPOPTSTRIP now uses the TCP
header itself to locate the option space, and the options are now
properly stripped. (BZ#1172026)

* The ipset utility computed incorrect values of timeouts from an old
IP set, and these values were then supplied to a new IP set. A resize
on an IP set with a timeouts option enabled could then supply
corrupted data from an old IP set. This bug has been fixed by properly
reading timeout values from an old set before supplying them to a new
set. (BZ#1172763)

* Incorrect processing of errors from the BCM5719 LAN controller could
result in incoming packets being dropped. Now, received errors are
handled properly, and incoming packets are no longer randomly dropped.
(BZ#1180405)

* When the NVMe driver allocated a name-space queue, it was recognized
as a request-based driver, whereas it was a BIO-based driver. While
trying to access data during the loading of NVMe along with a
request-based DM device, the system could terminate unexpectedly or
become unresponsive. Now, NVMe does not set the QUEUE_FLAG_STACKABLE
flag during the allocation of a name-space queue, and the system no
longer attempts to insert a request into the queue, preventing a
crash. (BZ#1180554)

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The system
must be rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4483.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3185.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3611.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3645.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3646.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-7841.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8160.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0284.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6\.5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.5", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:0284";
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
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"kernel-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", reference:"kernel-abi-whitelists-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"kernel-debug-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-debug-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-debug-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"kernel-debug-devel-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-debug-devel-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"kernel-debuginfo-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-debuginfo-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-debuginfo-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"kernel-devel-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-devel-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-devel-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", reference:"kernel-doc-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", reference:"kernel-firmware-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"kernel-headers-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-headers-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-headers-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-kdump-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-kdump-devel-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"perf-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"perf-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"perf-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"perf-debuginfo-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"perf-debuginfo-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"perf-debuginfo-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"python-perf-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"python-perf-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"python-perf-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"python-perf-debuginfo-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"python-perf-debuginfo-2.6.32-431.50.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"python-perf-debuginfo-2.6.32-431.50.1.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / etc");
  }
}
