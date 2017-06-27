#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0662. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78954);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/05 16:17:31 $");

  script_cve_id("CVE-2013-0871");
  script_bugtraq_id(57986);
  script_xref(name:"RHSA", value:"2013:0662");

  script_name(english:"RHEL 6 : kernel (RHSA-2013:0662)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix one security issue and several bugs
are now available for Red Hat Enterprise Linux 6.3 Extended Update
Support.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issue :

* A race condition was found in the way the Linux kernel's ptrace
implementation handled PTRACE_SETREGS requests when the debuggee was
woken due to a SIGKILL signal instead of being stopped. A local,
unprivileged user could use this flaw to escalate their privileges.
(CVE-2013-0871, Important)

This update also fixes the following bugs :

* Previously, init scripts were unable to set the MAC address of the
master interface properly because it was overwritten by the first
slave MAC address. To avoid this problem, this update re-introduces
the check for an unassigned MAC address before setting the MAC address
of the first slave interface as the MAC address of the master
interface. (BZ#908735)

* When using transparent proxy (TProxy) over IPv6, the kernel
previously created neighbor entries for local interfaces and peers
that were not reachable directly. This update corrects this problem
and the kernel no longer creates invalid neighbor entries. (BZ#909158)

* Due to the incorrect validation of a pointer dereference in the
d_validate() function, running a command such as ls or find on the
MultiVersion File System (MVFS), used by IBM Rational ClearCase, for
example, could trigger a kernel panic. This update modifies
d_validate() to verify the parent-child dentry relationship by
searching through the parent's d_child list. The kernel no longer
panics in this situation. (BZ#915582)

* A previously backported patch introduced usage of the page_descs
length field but did not set the page data length for the FUSE page
descriptor. This code path can be exercised by a loopback device
(pagecache_write_end) if used over FUSE. As a result, fuse_copy_page
does not copy page data from the page descriptor to the user-space
request buffer and the user space can see uninitialized data. This
could previously lead to file system data corruption. This problem has
been fixed by setting the page_descs length prior to submitting the
requests, and FUSE therefore provides correctly initialized data.
(BZ#916956)

Users should upgrade to these updated packages, which contain
backported patches to resolve these issues. The system must be
rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0871.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0662.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6\.3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.3", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0662";
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
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-debug-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-debug-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-debug-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-debug-devel-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-debug-devel-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-debuginfo-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-debuginfo-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-debuginfo-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-devel-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-devel-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-devel-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", reference:"kernel-doc-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", reference:"kernel-firmware-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-headers-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-headers-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-headers-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-kdump-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-kdump-devel-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"perf-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"perf-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"perf-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"perf-debuginfo-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"perf-debuginfo-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"perf-debuginfo-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"python-perf-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"python-perf-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"python-perf-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"python-perf-debuginfo-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"python-perf-debuginfo-2.6.32-279.23.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"python-perf-debuginfo-2.6.32-279.23.1.el6")) flag++;

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
