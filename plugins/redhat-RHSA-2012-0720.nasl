#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0720. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64039);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/05 16:04:22 $");

  script_cve_id("CVE-2012-0217", "CVE-2012-1583");
  script_bugtraq_id(53139);
  script_xref(name:"RHSA", value:"2012:0720");

  script_name(english:"RHEL 5 : kernel (RHSA-2012:0720)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix two security issues and multiple bugs
are now available for Red Hat Enterprise Linux 5.6 Extended Update
Support.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

[Updated 19th June 2012] The original erratum text provided an
incorrect description for BZ#807929. The text has been updated to
provide the correct description. No changes have been made to the
packages.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* It was found that the Xen hypervisor implementation as shipped with
Red Hat Enterprise Linux 5 did not properly restrict the syscall
return addresses in the sysret return path to canonical addresses. An
unprivileged user in a 64-bit para-virtualized guest, that is running
on a 64-bit host that has an Intel CPU, could use this flaw to crash
the host or, potentially, escalate their privileges, allowing them to
execute arbitrary code at the hypervisor level. (CVE-2012-0217,
Important)

Note: For Red Hat Enterprise Linux guests, only privileged guest users
can exploit CVE-2012-0217.

* A flaw in the xfrm6_tunnel_rcv() function in the Linux kernel's IPv6
implementation could lead to a use-after-free or double free flaw in
tunnel6_rcv(). A remote attacker could use this flaw to send specially
crafted packets to a target system that is using IPv6 and also has the
xfrm6_tunnel kernel module loaded, causing it to crash.
(CVE-2012-1583, Important)

If you do not run applications that use xfrm6_tunnel, you can prevent
the xfrm6_tunnel module from being loaded by creating (as the root
user) a '/etc/modprobe.d/xfrm6_tunnel.conf' file, and adding the
following line to it :

blacklist xfrm6_tunnel

This way, the xfrm6_tunnel module cannot be loaded accidentally. A
reboot is not necessary for this change to take effect.

Red Hat would like to thank the Xen project for reporting
CVE-2012-0217. Upstream acknowledges Rafal Wojtczuk as the original
reporter of CVE-2012-0217.

This update also fixes the following bugs :

* A bug in the vsyscall interface caused 32-bit multi-threaded
programs, which received the SIGCANCEL signal right after they
returned from a system call, to terminate unexpectedly with a
segmentation fault when run on the AMD64 or Intel 64 architecture. A
patch has been provided to address this issue and the crashes no
longer occur in the described scenario. (BZ#807929)

* Incorrect duplicate MAC addresses were being used on a rack network
daughter card that contained a quad-port Intel I350 Gigabit Ethernet
Controller. With this update, the underlying source code has been
modified to address this issue, and correct MAC addresses are now used
under all circumstances. (BZ#813195)

* When the Fibre Channel (FC) layer sets a device to 'running', the
layer also scans for other new devices. Previously, there was a race
condition between these two operations. Consequently, for certain
targets, thousands of invalid devices were created by the SCSI layer
and the udev service. This update ensures that the FC layer always
sets a device to 'online' before scanning for others, thus fixing this
bug.

Additionally, when attempting to transition priority groups on a busy
FC device, the multipath layer retried immediately. If this was the
only available path, a large number of retry operations were performed
in a short period of time. Consequently, the logging of retry messages
slowed down the system. This bug has been fixed by ensuring that the
DM Multipath feature delays retry operations in the described
scenario. (BZ#816683)

* Due to incorrect use of the list_for_each_entry_safe() macro, the
enumeration of remote procedure calls (RPCs) priority wait queue tasks
stored in the tk_wait.links list failed. As a consequence, the
rpc_wake_up() and rpc_wake_up_status() functions failed to wake up all
tasks. This caused the system to become unresponsive and could
significantly decrease system performance. Now, the
list_for_each_entry_safe() macro is no longer used in rpc_wake_up(),
ensuring reasonable system performance. (BZ#817570)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0217.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1583.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0720.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5\.6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.6", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:0720";
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
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-PAE-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-PAE-debuginfo-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-PAE-devel-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-debug-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-debug-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-debug-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-debug-devel-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-debug-devel-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-debug-devel-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-debuginfo-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-debuginfo-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-debuginfo-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-debuginfo-common-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-debuginfo-common-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-debuginfo-common-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-devel-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-devel-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-devel-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", reference:"kernel-doc-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"kernel-headers-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-headers-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-headers-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-kdump-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-kdump-devel-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-xen-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-xen-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-xen-debuginfo-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-xen-debuginfo-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-xen-devel-2.6.18-238.39.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-xen-devel-2.6.18-238.39.1.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-PAE / kernel-PAE-debuginfo / kernel-PAE-devel / etc");
  }
}
