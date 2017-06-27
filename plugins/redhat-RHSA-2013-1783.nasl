#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1783. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78983);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2012-4508", "CVE-2013-2851", "CVE-2013-4299");
  script_bugtraq_id(56238, 60409, 63183);
  script_osvdb_id(88156, 94035, 98634);
  script_xref(name:"RHSA", value:"2013:1783");

  script_name(english:"RHEL 6 : kernel (RHSA-2013:1783)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix three security issues and several
bugs are now available for Red Hat Enterprise Linux 6.3 Extended
Update Support.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* A race condition was found in the way asynchronous I/O and
fallocate() interacted when using the ext4 file system. A local,
unprivileged user could use this flaw to expose random data from an
extent whose data blocks have not yet been written, and thus contain
data from a deleted file. (CVE-2012-4508, Important)

* An information leak flaw was found in the way the Linux kernel's
device mapper subsystem, under certain conditions, interpreted data
written to snapshot block devices. An attacker could use this flaw to
read data from disk blocks in free space, which are normally
inaccessible. (CVE-2013-4299, Moderate)

* A format string flaw was found in the Linux kernel's block layer. A
privileged, local user could potentially use this flaw to escalate
their privileges to kernel level (ring0). (CVE-2013-2851, Low)

Red Hat would like to thank Theodore Ts'o for reporting CVE-2012-4508,
Fujitsu for reporting CVE-2013-4299, and Kees Cook for reporting
CVE-2013-2851. Upstream acknowledges Dmitry Monakhov as the original
reporter of CVE-2012-4508.

This update also fixes several bugs. Documentation for these changes
will be available shortly from the Technical Notes document linked to
in the References section.

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The system
must be rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4508.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2851.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4299.html"
  );
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux/6/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64c6b598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1783.html"
  );
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6b506c4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/05");
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
  rhsa = "RHSA-2013:1783";
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
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-debug-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-debug-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-debug-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-debug-devel-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-debug-devel-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-debuginfo-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-debuginfo-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-debuginfo-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-devel-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-devel-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-devel-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", reference:"kernel-doc-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", reference:"kernel-firmware-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"kernel-headers-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-headers-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"kernel-headers-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-kdump-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"kernel-kdump-devel-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"perf-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"perf-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"perf-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"perf-debuginfo-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"perf-debuginfo-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"perf-debuginfo-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"python-perf-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"python-perf-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"python-perf-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"python-perf-debuginfo-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"python-perf-debuginfo-2.6.32-279.39.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"python-perf-debuginfo-2.6.32-279.39.1.el6")) flag++;

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
