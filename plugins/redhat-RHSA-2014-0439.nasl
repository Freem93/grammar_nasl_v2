#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0439. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76674);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/03/08 15:07:20 $");

  script_cve_id(
    "CVE-2013-4483",
    "CVE-2013-7263",
    "CVE-2013-7265",
    "CVE-2013-7339",
    "CVE-2014-0069",
    "CVE-2014-1438",
    "CVE-2014-1690",
    "CVE-2014-1874",
    "CVE-2014-2309",
    "CVE-2014-2523"
  );
  script_bugtraq_id(
    64677,
    64686,
    64781,
    65180,
    65459,
    65588,
    66095,
    66279
  );
  script_osvdb_id(
    99161,
    100422,
    101515,
    101787,
    102604,
    102931,
    103646,
    104211,
    104658,
    104894
  );
  script_xref(name:"RHSA", value:"2014:0439");

  script_name(english:"RHEL 6 : MRG (RHSA-2014:0439)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Updated kernel-rt packages that fix multiple security issues, several
bugs, and add various enhancements are now available for Red Hat
Enterprise MRG 2.5.

The Red Hat Security Response Team has rated this update as having
Important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel-rt packages contain the Linux kernel, the core of any Linux
operating system.

  * A denial of service flaw was found in the way the Linux
    kernel's IPv6 implementation processed IPv6 router
    advertisement (RA) packets. An attacker able to send a
    large number of RA packets to a target system could
    potentially use this flaw to crash the target system.
    (CVE-2014-2309, Important)

  * A flaw was found in the way the Linux kernel's netfilter
    connection tracking implementation for Datagram
    Congestion Control Protocol (DCCP) packets used the
    skb_header_pointer() function. A remote attacker could
    use this flaw to send a specially crafted DCCP packet
    to crash the system or, potentially, escalate their
    privileges on the system. (CVE-2014-2523, Important)

  * A flaw was found in the way the Linux kernel's CIFS
    implementation handled uncached write operations with
    specially crafted iovec structures. An unprivileged
    local user with access to a CIFS share could use this
    flaw to crash the system, leak kernel memory, or,
    potentially, escalate their privileges on the system.
    (CVE-2014-0069, Moderate)

  * A flaw was found in the way the Linux kernel handled
    pending Floating Pointer Unit (FPU) exceptions during
    the switching of tasks. A local attacker could use this
    flaw to terminate arbitrary processes on the system,
    causing a denial of service, or, potentially, escalate
    their privileges on the system. Note that this flaw only
    affected systems using AMD CPUs on both 32-bit and
    64-bit architectures. (CVE-2014-1438, Moderate)

  * It was found that certain protocol handlers in the Linux
    kernel's networking implementation could set the
    addr_len value without initializing the associated data
    structure. A local, unprivileged user could use this
    flaw to leak kernel stack memory to user space using the
    recvmsg, recvfrom, and recvmmsg system calls.
    (CVE-2013-7263, CVE-2013-7265, Low)

  * An information leak flaw was found in the Linux kernel's
    netfilter connection tracking IRC NAT helper
    implementation that could allow a remote attacker to
    disclose portions of kernel stack memory during IRC
    DCC (Direct Client-to-Client) communication over NAT.
    (CVE-2014-1690, Low)

  * A denial of service flaw was discovered in the way the
    Linux kernel's SELinux implementation handled files with
    an empty SELinux security context. A local user who has
    the CAP_MAC_ADMIN capability could use this flaw to
    crash the system. (CVE-2014-1874, Low)

This update also fixes several bugs and adds multiple enhancements.
Documentation for these changes will be available shortly from the
Technical Notes document linked to in the References section.

Users are advised to upgrade to these updated packages, which upgrade
the kernel-rt kernel to version kernel-rt-3.10.33-rt32.33, correct
these issues, and fix the bugs and add the enhancements noted in the
Red Hat Enterprise MRG 2 Technical Notes. The system must be rebooted
for this update to take effect.");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-4483.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-7263.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-7265.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-7339.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-0069.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-1438.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-1690.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-1874.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-2309.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-2523.html");
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_MRG/2/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae491241");
  script_set_attribute(attribute:"see_also", value:"http://rhn.redhat.com/errata/RHSA-2014-0439.html");
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_MRG/2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?687515f3");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

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
  rhsa = "RHSA-2014:0439";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"mrg-release"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "MRG");

  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-3.10.33-rt32.33.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-debug-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-3.10.33-rt32.33.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-debug-debuginfo-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-debuginfo-3.10.33-rt32.33.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-debug-devel-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-devel-3.10.33-rt32.33.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-debuginfo-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debuginfo-3.10.33-rt32.33.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-debuginfo-common-x86_64-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debuginfo-common-x86_64-3.10.33-rt32.33.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-devel-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-devel-3.10.33-rt32.33.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-doc-3.10.0-") && rpm_check(release:"RHEL6", reference:"kernel-rt-doc-3.10.33-rt32.33.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-firmware-3.10.0-") && rpm_check(release:"RHEL6", reference:"kernel-rt-firmware-3.10.33-rt32.33.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-trace-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-3.10.33-rt32.33.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-trace-debuginfo-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-debuginfo-3.10.33-rt32.33.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-trace-devel-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-devel-3.10.33-rt32.33.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-vanilla-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-3.10.33-rt32.33.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-vanilla-debuginfo-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-debuginfo-3.10.33-rt32.33.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-vanilla-devel-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-devel-3.10.33-rt32.33.el6rt")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-rt / kernel-rt-debug / kernel-rt-debug-debuginfo / etc");
  }
}
