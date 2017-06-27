#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1199. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84486);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/01/06 16:01:52 $");

  script_cve_id("CVE-2015-1805", "CVE-2015-3331");
  script_osvdb_id(121011, 122968);
  script_xref(name:"RHSA", value:"2015:1199");

  script_name(english:"RHEL 6 : kernel (RHSA-2015:1199)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix two security issues and three bugs
are now available for Red Hat Enterprise Linux 6.5 Extended Update
Support.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* It was found that the Linux kernel's implementation of vectored pipe
read and write functionality did not take into account the I/O vectors
that were already processed when retrying after a failed atomic access
operation, potentially resulting in memory corruption due to an I/O
vector array overrun. A local, unprivileged user could use this flaw
to crash the system or, potentially, escalate their privileges on the
system. (CVE-2015-1805, Important)

* A buffer overflow flaw was found in the way the Linux kernel's Intel
AES-NI instructions optimized version of the RFC4106 GCM mode
decryption functionality handled fragmented packets. A remote attacker
could use this flaw to crash, or potentially escalate their privileges
on, a system over a connection with an active AES-GCM mode IPSec
security association. (CVE-2015-3331, Important)

The security impact of the CVE-2015-1805 issue was discovered by Red
Hat.

This update also fixes the following bugs :

* Parallel extending direct I/O writes to a file could previously race
to update the size of the file. If executed in an incorrect order, the
file size could move backwards and push a previously completed write
beyond the end of the file, which resulted in losing the write. With
this update, file size updates always execute in appropriate order,
thus fixing this bug. (BZ#1218498)

* When the load rose and run queues were busy due to the effects of
the enqueue_entity() function, tasks with large sched_entity.vruntime
values could previously be prevented from using the CPU time. A patch
eliminating the entity_key() function in the sched_fair.c latency
value has been backported from upstream, and all tasks are now
provided with fair CPU runtime. (BZ#1219121)

* Previously, running the clock_gettime() function quickly in a loop
could result in a jump back in time. Consequently, programs could
behave unexpectedly when they assumed that clock_getime() returned an
equal or greater time in subsequent calls. With this update, if the
time delta between calls is negative, the clock is no longer updated.
As a result, a subsequent call to clock_gettime() is guaranteed to
return a time greater than or equal to a previous call. (BZ#1219500)

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The system
must be rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-1805.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-3331.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-1199.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6\.5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.5", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:1199";
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
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"kernel-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", reference:"kernel-abi-whitelists-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"kernel-debug-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-debug-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-debug-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"kernel-debug-devel-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-debug-devel-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"kernel-debuginfo-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-debuginfo-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-debuginfo-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"kernel-devel-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-devel-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-devel-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", reference:"kernel-doc-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", reference:"kernel-firmware-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"kernel-headers-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-headers-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-headers-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-kdump-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"kernel-kdump-devel-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"perf-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"perf-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"perf-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"perf-debuginfo-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"perf-debuginfo-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"perf-debuginfo-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"python-perf-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"python-perf-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"python-perf-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"python-perf-debuginfo-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"python-perf-debuginfo-2.6.32-431.59.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"python-perf-debuginfo-2.6.32-431.59.1.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / etc");
  }
}
