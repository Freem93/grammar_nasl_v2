#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1083. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77298);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/03/08 15:07:20 $");

  script_cve_id(
    "CVE-2014-4652",
    "CVE-2014-4653",
    "CVE-2014-4654",
    "CVE-2014-4655",
    "CVE-2014-4656",
    "CVE-2014-5077"
  );
  script_bugtraq_id(
    68162,
    68163,
    68164,
    68170,
    68881
  );
  script_osvdb_id(
    108386,
    108387,
    108388,
    108389,
    108390,
    108451,
    109512
  );
  script_xref(name:"RHSA", value:"2014:1083");

  script_name(english:"RHEL 6 : MRG (RHSA-2014:1083)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Updated kernel-rt packages that fix multiple security issues and one
bug are now available for Red Hat Enterprise MRG 2.5.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The kernel-rt packages contain the Linux kernel, the core of any Linux
operating system.

  * A NULL pointer dereference flaw was found in the way
    the Linux kernel's Stream Control Transmission Protocol
    (SCTP) implementation handled simultaneous connections
    between the same hosts. A remote attacker could use this
    flaw to crash the system. (CVE-2014-5077, Important)

  * Multiple use-after-free flaws and an integer overflow
    flaw were found in the way the Linux kernel's Advanced
    Linux Sound Architecture (ALSA) implementation handled
    user controls. A local, privileged user could use either
    of these flaws to crash the system. (CVE-2014-4653,
    CVE-2014-4654, CVE-2014-4655, CVE-2014-4656, Moderate)

  * An information leak flaw was found in the way the Linux
    kernel's Advanced Linux Sound Architecture (ALSA)
    implementation handled access of the user control's
    state. A local, privileged user could use this flaw to
    leak kernel memory to user space. (CVE-2014-4652, Low)

This update also fixes the following bug :

  * Prior to this update, the netconsole module was
    unavailable on MRG Realtime kernels due to locking
    issues that disabled it. These locking issues have been
    corrected, allowing the netconsole module to be
    re-enabled and functional on Realtime kernels.
    (BZ#1088923)

Users are advised to upgrade to these updated packages, which upgrade
the kernel-rt kernel to version kernel-rt-3.10.33-rt32.45 and correct
these issues. The system must be rebooted for this update to take
effect.");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-4652.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-4653.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-4654.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-4655.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-4656.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2014-5077.html");
  script_set_attribute(attribute:"see_also", value:"http://rhn.redhat.com/errata/RHSA-2014-1083.html");
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/21");

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
  rhsa = "RHSA-2014:1083";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"mrg-release"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "MRG");

  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-3.10.33-rt32.45.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-debug-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-3.10.33-rt32.45.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-debug-debuginfo-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-debuginfo-3.10.33-rt32.45.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-debug-devel-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-devel-3.10.33-rt32.45.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-debuginfo-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debuginfo-3.10.33-rt32.45.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-debuginfo-common-x86_64-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debuginfo-common-x86_64-3.10.33-rt32.45.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-devel-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-devel-3.10.33-rt32.45.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-doc-3.10.0-") && rpm_check(release:"RHEL6", reference:"kernel-rt-doc-3.10.33-rt32.45.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-firmware-3.10.0-") && rpm_check(release:"RHEL6", reference:"kernel-rt-firmware-3.10.33-rt32.45.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-trace-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-3.10.33-rt32.45.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-trace-debuginfo-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-debuginfo-3.10.33-rt32.45.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-trace-devel-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-devel-3.10.33-rt32.45.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-vanilla-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-3.10.33-rt32.45.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-vanilla-debuginfo-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-debuginfo-3.10.33-rt32.45.el6rt")) flag++;
  if (! rpm_exists(release:"RHEL6", rpm:"kernel-rt-vanilla-devel-3.10.0-") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-devel-3.10.33-rt32.45.el6rt")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-rt / kernel-rt-debug / kernel-rt-debug-debuginfo / etc");
  }
}
