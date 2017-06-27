#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1304. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62303);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/01/05 16:17:29 $");

  script_cve_id("CVE-2012-2313", "CVE-2012-2384", "CVE-2012-2390", "CVE-2012-3430", "CVE-2012-3552");
  script_bugtraq_id(53668, 53965, 53971, 54702, 55359);
  script_osvdb_id(82808, 83073, 83185, 85606, 85723);
  script_xref(name:"RHSA", value:"2012:1304");

  script_name(english:"RHEL 6 : kernel (RHSA-2012:1304)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* An integer overflow flaw was found in the i915_gem_do_execbuffer()
function in the Intel i915 driver in the Linux kernel. A local,
unprivileged user could use this flaw to cause a denial of service.
This issue only affected 32-bit systems. (CVE-2012-2384, Moderate)

* A memory leak flaw was found in the way the Linux kernel's memory
subsystem handled resource clean up in the mmap() failure path when
the MAP_HUGETLB flag was set. A local, unprivileged user could use
this flaw to cause a denial of service. (CVE-2012-2390, Moderate)

* A race condition was found in the way access to inet->opt ip_options
was synchronized in the Linux kernel's TCP/IP protocol suite
implementation. Depending on the network facing applications running
on the system, a remote attacker could possibly trigger this flaw to
cause a denial of service. A local, unprivileged user could use this
flaw to cause a denial of service regardless of the applications the
system runs. (CVE-2012-3552, Moderate)

* A flaw was found in the way the Linux kernel's dl2k driver, used by
certain D-Link Gigabit Ethernet adapters, restricted IOCTLs. A local,
unprivileged user could use this flaw to issue potentially harmful
IOCTLs, which could cause Ethernet adapters using the dl2k driver to
malfunction (for example, losing network connectivity).
(CVE-2012-2313, Low)

* A flaw was found in the way the msg_namelen variable in the
rds_recvmsg() function of the Linux kernel's Reliable Datagram Sockets
(RDS) protocol implementation was initialized. A local, unprivileged
user could use this flaw to leak kernel stack memory to user-space.
(CVE-2012-3430, Low)

Red Hat would like to thank Hafid Lin for reporting CVE-2012-3552, and
Stephan Mueller for reporting CVE-2012-2313. The CVE-2012-3430 issue
was discovered by the Red Hat InfiniBand team.

This update also fixes several bugs. Documentation for these changes
will be available shortly from the Technical Notes document linked to
in the References section.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues, and fix the bugs noted in
the Technical Notes. The system must be rebooted for this update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2313.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2384.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2390.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3430.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3552.html"
  );
  # https://access.redhat.com/knowledge/docs/en-US/Red_Hat_Enterprise_Linux/6/html/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?faae67f0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-1304.html"
  );
  # https://access.redhat.com/knowledge/docs/en-US/Red_Hat_Enterprise_Linux/6/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?879a0985"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2012:1304";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debug-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debug-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debug-devel-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debug-devel-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debuginfo-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debuginfo-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-devel-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-devel-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-devel-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"kernel-doc-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"kernel-firmware-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-headers-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-headers-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-headers-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-kdump-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-kdump-devel-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"perf-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perf-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perf-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"perf-debuginfo-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perf-debuginfo-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perf-debuginfo-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-perf-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-perf-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-perf-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-perf-debuginfo-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-perf-debuginfo-2.6.32-279.9.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-perf-debuginfo-2.6.32-279.9.1.el6")) flag++;


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
