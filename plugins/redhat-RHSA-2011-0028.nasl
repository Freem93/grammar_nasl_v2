#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0028. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63968);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/04 16:02:21 $");

  script_cve_id("CVE-2010-4525");
  script_bugtraq_id(45676);
  script_xref(name:"RHSA", value:"2011:0028");

  script_name(english:"RHEL 5 : kvm (RHSA-2011:0028)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kvm packages that fix one security issue and several bugs are
now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. KVM is a Linux kernel module
built for the standard Red Hat Enterprise Linux kernel.

A data structure field in kvm_vcpu_ioctl_x86_get_vcpu_events() in
QEMU-KVM was not initialized properly before being copied to
user-space. A privileged host user with access to '/dev/kvm' could use
this flaw to leak kernel stack memory to user-space. (CVE-2010-4525)

Red Hat would like to thank Stephan Mueller of atsec information
security for reporting this issue.

These updated packages also fix several bugs. Documentation for these
bug fixes will be available shortly in the 'kvm' section of the Red
Hat Enterprise Linux 5.6 Technical Notes, linked to in the References.

All KVM users should upgrade to these updated packages, which resolve
this issue as well as fixing the bugs noted in the Technical Notes.
Note: The procedure in the Solution section must be performed before
this update will take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-4525.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/5/html/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0028.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kmod-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kmod-kvm-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kvm-qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/13");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:0028";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kmod-kvm-83-224.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kmod-kvm-debug-83-224.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kvm-83-224.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kvm-qemu-img-83-224.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kvm-tools-83-224.el5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kmod-kvm / kmod-kvm-debug / kvm / kvm-qemu-img / kvm-tools");
  }
}
