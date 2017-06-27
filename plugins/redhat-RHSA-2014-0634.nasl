#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0634. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79028);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/06 15:40:57 $");

  script_cve_id("CVE-2013-6383", "CVE-2014-0077", "CVE-2014-2523");
  script_bugtraq_id(63888, 66279, 66678);
  script_xref(name:"RHSA", value:"2014:0634");

  script_name(english:"RHEL 6 : kernel (RHSA-2014:0634)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix three security issues and several
bugs are now available for Red Hat Enterprise Linux 6.4 Extended
Update Support.

The Red Hat Security Response Team has rated this update as having
Important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* A flaw was found in the way the Linux kernel's netfilter connection
tracking implementation for Datagram Congestion Control Protocol
(DCCP) packets used the skb_header_pointer() function. A remote
attacker could use this flaw to send a specially crafted DCCP packet
to crash the system or, potentially, escalate their privileges on the
system. (CVE-2014-2523, Important)

* A flaw was found in the way the Linux kernel's Adaptec RAID
controller (aacraid) checked permissions of compat IOCTLs. A local
attacker could use this flaw to bypass intended security restrictions.
(CVE-2013-6383, Moderate)

* A flaw was found in the way the handle_rx() function handled large
network packets when mergeable buffers were disabled. A privileged
guest user could use this flaw to crash the host or corrupt QEMU
process memory on the host, which could potentially result in
arbitrary code execution on the host with the privileges of the QEMU
process. (CVE-2014-0077, Moderate)

The CVE-2014-0077 issue was discovered by Michael S. Tsirkin of Red
Hat.

This update also fixes several bugs. Documentation for these changes
will be available shortly from the Technical Notes document linked to
in the References section.

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The system
must be rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-6383.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0077.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-2523.html"
  );
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux/6/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64c6b598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-0634.html"
  );
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6b506c4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/04");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:0634";
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
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"kernel-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"kernel-debug-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-debug-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"kernel-debug-devel-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-debug-devel-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"kernel-debuginfo-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-debuginfo-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"kernel-devel-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-devel-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-devel-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"kernel-doc-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"kernel-firmware-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"kernel-headers-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-headers-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-headers-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-kdump-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"kernel-kdump-devel-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"perf-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"perf-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perf-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"perf-debuginfo-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"perf-debuginfo-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perf-debuginfo-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"python-perf-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"python-perf-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"python-perf-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"python-perf-debuginfo-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"python-perf-debuginfo-2.6.32-358.44.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-perf-debuginfo-2.6.32-358.44.1.el6")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debug / kernel-debug-debuginfo / kernel-debug-devel / etc");
  }
}
