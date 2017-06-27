#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1114. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64049);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/05 16:04:22 $");

  script_cve_id("CVE-2012-2744");
  script_bugtraq_id(54367);
  script_xref(name:"RHSA", value:"2012:1114");

  script_name(english:"RHEL 6 : kernel (RHSA-2012:1114)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix one security issue are now available
for Red Hat Enterprise Linux 6.0 Extended Update Support.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issue :

* A NULL pointer dereference flaw was found in the nf_ct_frag6_reasm()
function in the Linux kernel's netfilter IPv6 connection tracking
implementation. A remote attacker could use this flaw to send
specially crafted packets to a target system that is using IPv6 and
also has the nf_conntrack_ipv6 kernel module loaded, causing it to
crash. (CVE-2012-2744, Important)

Red Hat would like to thank an anonymous contributor working with the
Beyond Security SecuriTeam Secure Disclosure program for reporting
this issue.

Users should upgrade to these updated packages, which contain a
backported patch to resolve this issue. The system must be rebooted
for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2744.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-1114.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/24");
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
if (! ereg(pattern:"^6\.0([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.0", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:1114";
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
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"i686", reference:"kernel-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"s390x", reference:"kernel-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"x86_64", reference:"kernel-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"i686", reference:"kernel-debug-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"s390x", reference:"kernel-debug-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"x86_64", reference:"kernel-debug-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"i686", reference:"kernel-debug-devel-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"s390x", reference:"kernel-debug-devel-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"i686", reference:"kernel-debuginfo-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"s390x", reference:"kernel-debuginfo-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"x86_64", reference:"kernel-debuginfo-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"i686", reference:"kernel-devel-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"s390x", reference:"kernel-devel-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"x86_64", reference:"kernel-devel-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", reference:"kernel-doc-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", reference:"kernel-firmware-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"i686", reference:"kernel-headers-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"s390x", reference:"kernel-headers-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"x86_64", reference:"kernel-headers-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"s390x", reference:"kernel-kdump-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", cpu:"s390x", reference:"kernel-kdump-devel-2.6.32-71.40.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"0", reference:"perf-2.6.32-71.40.1.el6")) flag++;

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
