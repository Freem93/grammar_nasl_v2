#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:092. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17183);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/28 17:55:17 $");

  script_cve_id("CVE-2004-1056", "CVE-2004-1137", "CVE-2004-1235", "CVE-2005-0001", "CVE-2005-0090", "CVE-2005-0091", "CVE-2005-0092", "CVE-2005-0176", "CVE-2005-0177", "CVE-2005-0178", "CVE-2005-0179", "CVE-2005-0180", "CVE-2005-0204");
  script_xref(name:"RHSA", value:"2005:092");

  script_name(english:"RHEL 4 : kernel (RHSA-2005:092)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix several security issues are now
available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

This advisory includes fixes for several security issues :

iSEC Security Research discovered multiple vulnerabilities in the IGMP
functionality. These flaws could allow a local user to cause a denial
of service (crash) or potentially gain privileges. Where multicast
applications are being used on a system, these flaws may also allow
remote users to cause a denial of service. The Common Vulnerabilities
and Exposures project (cve.mitre.org) has assigned the name
CVE-2004-1137 to this issue.

iSEC Security Research discovered a flaw in the page fault handler
code that could lead to local users gaining elevated (root) privileges
on multiprocessor machines. (CVE-2005-0001)

iSEC Security Research discovered a VMA handling flaw in the uselib(2)
system call of the Linux kernel. A local user could make use of this
flaw to gain elevated (root) privileges. (CVE-2004-1235)

A flaw affecting the OUTS instruction on the AMD64 and Intel EM64T
architecture was discovered. A local user could use this flaw to write
to privileged IO ports. (CVE-2005-0204)

The Direct Rendering Manager (DRM) driver in Linux kernel 2.6 does not
properly check the DMA lock, which could allow remote attackers or
local users to cause a denial of service (X Server crash) or possibly
modify the video output. (CVE-2004-1056)

OGAWA Hirofumi discovered incorrect tables sizes being used in the
filesystem Native Language Support ASCII translation table. This could
lead to a denial of service (system crash). (CVE-2005-0177)

Michael Kerrisk discovered a flaw in the 2.6.9 kernel which allows
users to unlock arbitrary shared memory segments. This flaw could lead
to applications not behaving as expected. (CVE-2005-0176)

Improvements in the POSIX signal and tty standards compliance exposed
a race condition. This flaw can be triggered accidentally by threaded
applications or deliberately by a malicious user and can result in a
denial of service (crash) or in occasional cases give access to a
small random chunk of kernel memory. (CVE-2005-0178)

The PaX team discovered a flaw in mlockall introduced in the 2.6.9
kernel. An unprivileged user could use this flaw to cause a denial of
service (CPU and memory consumption or crash). (CVE-2005-0179)

Brad Spengler discovered multiple flaws in sg_scsi_ioctl in the 2.6
kernel. An unprivileged user may be able to use this flaw to cause a
denial of service (crash) or possibly other actions. (CVE-2005-0180)

Kirill Korotaev discovered a missing access check regression in the
Red Hat Enterprise Linux 4 kernel 4GB/4GB split patch. On systems
using the hugemem kernel, a local unprivileged user could use this
flaw to cause a denial of service (crash). (CVE-2005-0090)

A flaw in the Red Hat Enterprise Linux 4 kernel 4GB/4GB split patch
can allow syscalls to read and write arbitrary kernel memory. On
systems using the hugemem kernel, a local unprivileged user could use
this flaw to gain privileges. (CVE-2005-0091)

An additional flaw in the Red Hat Enterprise Linux 4 kernel 4GB/4GB
split patch was discovered. On x86 systems using the hugemem kernel, a
local unprivileged user may be able to use this flaw to cause a denial
of service (crash). (CVE-2005-0092)

All Red Hat Enterprise Linux 4 users are advised to upgrade their
kernels to the packages associated with their machine architectures
and configurations as listed in this erratum."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1056.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1137.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1235.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0090.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0091.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0092.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0176.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0177.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0178.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0179.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0180.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0204.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.isec.pl/vulnerabilities/isec-0018-igmp.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.isec.pl/vulnerabilities/isec-0021-uselib.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.isec.pl/vulnerabilities/isec-0022-pagefault.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-092.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2005:092";
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
  if (rpm_check(release:"RHEL4", reference:"kernel-2.6.9-5.0.3.EL")) flag++;
  if (rpm_check(release:"RHEL4", reference:"kernel-devel-2.6.9-5.0.3.EL")) flag++;
  if (rpm_check(release:"RHEL4", reference:"kernel-doc-2.6.9-5.0.3.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-hugemem-2.6.9-5.0.3.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-hugemem-devel-2.6.9-5.0.3.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-smp-2.6.9-5.0.3.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-smp-2.6.9-5.0.3.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-smp-devel-2.6.9-5.0.3.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-5.0.3.EL")) flag++;

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
