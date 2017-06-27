#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0508. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33376);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2017/01/03 17:16:33 $");

  script_cve_id("CVE-2008-0598", "CVE-2008-1367", "CVE-2008-2365", "CVE-2008-2729");
  script_bugtraq_id(29942);
  script_osvdb_id(48115, 48563, 48781);
  script_xref(name:"RHSA", value:"2008:0508");

  script_name(english:"RHEL 4 : kernel (RHSA-2008:0508)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix several security issues and a bug are
now available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

These updated packages fix the following security issues :

* A security flaw was found in the Linux kernel memory copy routines,
when running on certain AMD64 systems. If an unsuccessful attempt to
copy kernel memory from source to destination memory locations
occurred, the copy routines did not zero the content at the
destination memory location. This could allow a local unprivileged
user to view potentially sensitive data. (CVE-2008-2729, Important)

* Alexey Dobriyan discovered a race condition in the Linux kernel
process-tracing system call, ptrace. A local unprivileged user could
use this flaw to cause a denial of service (kernel hang).
(CVE-2008-2365, Important)

* Tavis Ormandy discovered a deficiency in the Linux kernel 32-bit and
64-bit emulation. This could allow a local unprivileged user to
prepare and run a specially crafted binary, which would use this
deficiency to leak uninitialized and potentially sensitive data.
(CVE-2008-0598, Important)

* It was discovered that the Linux kernel handled string operations in
the opposite way to the GNU Compiler Collection (GCC). This could
allow a local unprivileged user to cause memory corruption.
(CVE-2008-1367, Low)

As well, these updated packages fix the following bug :

* On systems with a large number of CPUs (more than 16), multiple
applications calling the 'times()' system call may have caused a
system hang.

Red Hat Enterprise Linux 4 users are advised to upgrade to these
updated packages, which contain backported patches to resolve these
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-0598.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1367.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-2365.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-2729.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0508.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-largesmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-largesmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xenU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xenU-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.6");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0508";
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
  if (rpm_check(release:"RHEL4", reference:"kernel-2.6.9-67.0.20.EL")) flag++;

  if (rpm_check(release:"RHEL4", reference:"kernel-devel-2.6.9-67.0.20.EL")) flag++;

  if (rpm_check(release:"RHEL4", reference:"kernel-doc-2.6.9-67.0.20.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-hugemem-2.6.9-67.0.20.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-hugemem-devel-2.6.9-67.0.20.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-67.0.20.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-67.0.20.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-smp-2.6.9-67.0.20.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-smp-2.6.9-67.0.20.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-smp-devel-2.6.9-67.0.20.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-67.0.20.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-xenU-2.6.9-67.0.20.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-xenU-2.6.9-67.0.20.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-xenU-devel-2.6.9-67.0.20.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-xenU-devel-2.6.9-67.0.20.EL")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-devel / kernel-doc / kernel-hugemem / etc");
  }
}
