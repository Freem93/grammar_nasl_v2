#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0557. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76677);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/03/08 15:07:20 $");

  script_cve_id(
    "CVE-2014-0100",
    "CVE-2014-0196",
    "CVE-2014-1737",
    "CVE-2014-1738",
    "CVE-2014-2672",
    "CVE-2014-2678",
    "CVE-2014-2706",
    "CVE-2014-2851",
    "CVE-2014-3122"
  );
  script_bugtraq_id(
    65952,
    66492,
    66543,
    66591,
    66779,
    67162,
    67282,
    67300,
    67302
  );
  script_osvdb_id(
    104212,
    105072,
    105194,
    105302,
    105712,
    106527,
    106646,
    106730,
    106731
  );
  script_xref(name:"RHSA", value:"2014:0557");

  script_name(english:"RHEL 6 : MRG (RHSA-2014:0557)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Updated kernel-rt packages that fix multiple security issues are now
available for Red Hat Enterprise MRG 2.5.

The Red Hat Security Response Team has rated this update as having
Important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel-rt packages contain the Linux kernel, the core of any Linux
operating system.

  * A race condition leading to a use-after-free flaw was
    found in the way the Linux kernel's TCP/IP protocol
    suite implementation handled the addition of fragments
    to the LRU (Last-Recently Used) list under certain
    conditions. A remote attacker could use this flaw to
    crash the system or, potentially, escalate their
    privileges on the system by sending a large amount of
    specially crafted fragmented packets to that system.
    (CVE-2014-0100, Important)

  * A race condition flaw, leading to heap-based buffer
    overflows, was found in the way the Linux kernel's N_TTY
    line discipline (LDISC) implementation handled
    concurrent processing of echo output and TTY write
    operations originating from user space when the
    underlying TTY driver was PTY. An unprivileged, local
    user could use this flaw to crash the system or,
    potentially, escalate their privileges on the system.
    (CVE-2014-0196, Important)

  * A flaw was found in the way the Linux kernel's floppy
    driver handled user space provided data in certain error
    code paths while processing FDRAWCMD IOCTL commands. A
    local user with write access to /dev/fdX could use this
    flaw to free (using the kfree() function) arbitrary
    kernel memory. (CVE-2014-1737, Important)

  * It was found that the Linux kernel's floppy driver
    leaked internal kernel memory addresses to user space
    during the processing of the FDRAWCMD IOCTL command. A
    local user with write access to /dev/fdX could use this
    flaw to obtain information about the kernel heap
    arrangement. (CVE-2014-1738, Low)

Note: A local user with write access to /dev/fdX could use these two
flaws (CVE-2014-1737 in combination with CVE-2014-1738) to escalate
their privileges on the system.

  * A use-after-free flaw was found in the way the
    ping_init_sock() function of the Linux kernel handled
    the group_info reference counter. A local, unprivileged
    user could use this flaw to crash the system or,
    potentially, escalate their privileges on the system.
    (CVE-2014-2851, Important)

  * It was found that a remote attacker could use a race
    condition flaw in the ath_tx_aggr_sleep() function to
    crash the system by creating large network traffic on
    the system's Atheros 9k wireless network adapter.
    (CVE-2014-2672, Moderate)

  * A NULL pointer dereference flaw was found in the
    rds_iw_laddr_check() function in the Linux kernel's
    implementation of Reliable Datagram Sockets (RDS). A
    local, unprivileged user could use this flaw to crash
    the system. (CVE-2014-2678, Moderate)

  * A race condition flaw was found in the way the Linux
    kernel's mac80211 subsystem implementation handled
    synchronization between TX and STA wake-up code paths.
    A remote attacker could use this flaw to crash the
    system. (CVE-2014-2706, Moderate)

  * It was found that the try_to_unmap_cluster() function in
    the Linux kernel's Memory Managment subsystem did not
    properly handle page locking in certain cases, which
    could potentially trigger the BUG_ON() macro in the
    mlock_vma_page() function. A local, unprivileged user
    could use this flaw to crash the system. (CVE-2014-3122,
    Moderate)

Users are advised to upgrade to these updated packages, which upgrade
the kernel-rt kernel to version kernel-rt-3.10.33-rt32.34 and correct
these issues. The system must be rebooted for this update to take
effect.");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-0100.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-0196.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-1737.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-1738.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-2672.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-2678.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-2706.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-2851.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-3122.html");
  script_set_attribute(attribute:"see_also", value:"http://rhn.redhat.com/errata/RHSA-2014-0557.html");
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/27");
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
  rhsa = "RHSA-2014:0557";
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

  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-3.10.33-rt32.34.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-debug-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-3.10.33-rt32.34.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-debug-debuginfo-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-debuginfo-3.10.33-rt32.34.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-debug-devel-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-devel-3.10.33-rt32.34.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-debuginfo-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debuginfo-3.10.33-rt32.34.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-debuginfo-common-x86_64-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debuginfo-common-x86_64-3.10.33-rt32.34.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-devel-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-devel-3.10.33-rt32.34.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-doc-3.10.0-") && rpm_check(release:"RHEL6", reference:"kernel-rt-doc-3.10.33-rt32.34.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-firmware-3.10.0-") && rpm_check(release:"RHEL6", reference:"kernel-rt-firmware-3.10.33-rt32.34.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-trace-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-3.10.33-rt32.34.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-trace-debuginfo-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-debuginfo-3.10.33-rt32.34.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-trace-devel-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-devel-3.10.33-rt32.34.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-vanilla-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-3.10.33-rt32.34.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-vanilla-debuginfo-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-debuginfo-3.10.33-rt32.34.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-vanilla-devel-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-devel-3.10.33-rt32.34.el6rt")) flag++;

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
