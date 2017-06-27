#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0882. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66705);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/05 16:29:43 $");

  script_cve_id("CVE-2012-4461", "CVE-2012-4542", "CVE-2013-0311", "CVE-2013-1767");
  script_bugtraq_id(56414, 58053, 58088, 58177);
  script_xref(name:"RHSA", value:"2013:0882");

  script_name(english:"RHEL 6 : kernel (RHSA-2013:0882)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 6.2 Extended
Update Support.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* A flaw was found in the way the vhost kernel module handled
descriptors that spanned multiple regions. A privileged guest user in
a KVM (Kernel-based Virtual Machine) guest could use this flaw to
crash the host or, potentially, escalate their privileges on the host.
(CVE-2013-0311, Important)

* A flaw was found in the way the KVM subsystem handled guests
attempting to run with the X86_CR4_OSXSAVE CPU feature flag set. On
hosts without the XSAVE CPU feature, a local, unprivileged user could
use this flaw to crash the host system. (The 'grep --color xsave
/proc/cpuinfo' command can be used to verify if your system has the
XSAVE CPU feature.) (CVE-2012-4461, Moderate)

* It was found that the default SCSI command filter does not
accommodate commands that overlap across device classes. A privileged
guest user could potentially use this flaw to write arbitrary data to
a LUN that is passed-through as read-only. (CVE-2012-4542, Moderate)

* A use-after-free flaw was found in the tmpfs implementation. A local
user able to mount and unmount a tmpfs file system could use this flaw
to cause a denial of service or, potentially, escalate their
privileges. (CVE-2013-1767, Low)

Red Hat would like to thank Jon Howell for reporting CVE-2012-4461.
CVE-2012-4542 was discovered by Paolo Bonzini of Red Hat.

This update also fixes the following bugs :

* Previously, when open(2) system calls were processed, the GETATTR
routine did not check to see if valid attributes were also returned.
As a result, the open() call succeeded with invalid attributes instead
of failing in such a case. This update adds the missing check, and the
open() call succeeds only when valid attributes are returned.
(BZ#960409)

* Previously, the fsync(2) system call incorrectly returned the EIO
(Input/Output) error instead of the ENOSPC (No space left on device)
error. This was due to incorrect error handling in the page cache.
This problem has been fixed and the correct error value is now
returned. (BZ#960418)

* In the RPC code, when a network socket backed up due to high network
traffic, a timer was set causing a retransmission, which in turn could
cause an even larger amount of network traffic to be generated. To
prevent this problem, the RPC code now waits for the socket to empty
instead of setting the timer. (BZ#960423)

* This update fixes a number of bugs in the be2iscsi driver for
ServerEngines BladeEngine 2 Open iSCSI devices. (BZ#955502)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4461.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4542.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0311.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1767.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0882.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/31");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0882";
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
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"kernel-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"kernel-debug-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-debug-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"kernel-debug-devel-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-debug-devel-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"kernel-debuginfo-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-debuginfo-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"kernel-devel-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-devel-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-devel-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"kernel-doc-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"kernel-firmware-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"kernel-headers-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-headers-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-headers-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-kdump-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"kernel-kdump-devel-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"perf-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"perf-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perf-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"perf-debuginfo-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"perf-debuginfo-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perf-debuginfo-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"python-perf-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"python-perf-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"python-perf-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"python-perf-debuginfo-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"python-perf-debuginfo-2.6.32-220.38.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-perf-debuginfo-2.6.32-220.38.1.el6")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debug / kernel-debug-debuginfo / kernel-debug-devel / etc");
  }
}
