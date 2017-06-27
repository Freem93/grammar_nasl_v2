#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0237. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32162);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/01/03 17:16:33 $");

  script_cve_id("CVE-2005-0504", "CVE-2007-6282", "CVE-2008-0007", "CVE-2008-1375", "CVE-2008-1615", "CVE-2008-1669");
  script_bugtraq_id(29003, 29076, 29081, 29086);
  script_osvdb_id(44874, 44929, 44930, 44992);
  script_xref(name:"RHSA", value:"2008:0237");

  script_name(english:"RHEL 4 : kernel (RHSA-2008:0237)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix various security issues and several
bugs are now available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

These updated packages fix the following security issues :

* the absence of a protection mechanism when attempting to access a
critical section of code has been found in the Linux kernel open file
descriptors control mechanism, fcntl. This could allow a local
unprivileged user to simultaneously execute code, which would
otherwise be protected against parallel execution. As well, a race
condition when handling locks in the Linux kernel fcntl functionality,
may have allowed a process belonging to a local unprivileged user to
gain re-ordered access to the descriptor table. (CVE-2008-1669,
Important)

* on AMD64 architectures, the possibility of a kernel crash was
discovered by testing the Linux kernel process-trace ability. This
could allow a local unprivileged user to cause a denial of service
(kernel crash). (CVE-2008-1615, Important)

* the absence of a protection mechanism when attempting to access a
critical section of code, as well as a race condition, have been found
in the Linux kernel file system event notifier, dnotify. This could
allow a local unprivileged user to get inconsistent data, or to send
arbitrary signals to arbitrary system processes. (CVE-2008-1375,
Important)

Red Hat would like to thank Nick Piggin for responsibly disclosing the
following issue :

* when accessing kernel memory locations, certain Linux kernel drivers
registering a fault handler did not perform required range checks. A
local unprivileged user could use this flaw to gain read or write
access to arbitrary kernel memory, or possibly cause a kernel crash.
(CVE-2008-0007, Important)

* the possibility of a kernel crash was found in the Linux kernel
IPsec protocol implementation, due to improper handling of fragmented
ESP packets. When an attacker controlling an intermediate router
fragmented these packets into very small pieces, it would cause a
kernel crash on the receiving node during packet reassembly.
(CVE-2007-6282, Important)

* a flaw in the MOXA serial driver could allow a local unprivileged
user to perform privileged operations, such as replacing firmware.
(CVE-2005-0504, Important)

As well, these updated packages fix the following bugs :

* multiple buffer overflows in the neofb driver have been resolved. It
was not possible for an unprivileged user to exploit these issues, and
as such, they have not been handled as security issues.

* a kernel panic, due to inconsistent detection of AGP aperture size,
has been resolved.

* a race condition in UNIX domain sockets may have caused 'recv()' to
return zero. In clustered configurations, this may have caused
unexpected failovers.

* to prevent link storms, network link carrier events were delayed by
up to one second, causing unnecessary packet loss. Now, link carrier
events are scheduled immediately.

* a client-side race on blocking locks caused large time delays on NFS
file systems.

* in certain situations, the libATA sata_nv driver may have sent
commands with duplicate tags, which were rejected by SATA devices.
This may have caused infinite reboots.

* running the 'service network restart' command may have caused
networking to fail.

* a bug in NFS caused cached information about directories to be
stored for too long, causing wrong attributes to be read.

* on systems with a large highmem/lowmem ratio, NFS write performance
may have been very slow when using small files.

* a bug, which caused network hangs when the system clock was wrapped
around zero, has been resolved.

Red Hat Enterprise Linux 4 users are advised to upgrade to these
updated packages, which contain backported patches to resolve these
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0504.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-6282.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-0007.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1375.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1615.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1669.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0237.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 94, 119, 362, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/09");
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
  rhsa = "RHSA-2008:0237";
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
  if (rpm_check(release:"RHEL4", reference:"kernel-2.6.9-67.0.15.EL")) flag++;

  if (rpm_check(release:"RHEL4", reference:"kernel-devel-2.6.9-67.0.15.EL")) flag++;

  if (rpm_check(release:"RHEL4", reference:"kernel-doc-2.6.9-67.0.15.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-hugemem-2.6.9-67.0.15.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-hugemem-devel-2.6.9-67.0.15.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-67.0.15.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-67.0.15.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-smp-2.6.9-67.0.15.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-smp-2.6.9-67.0.15.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-smp-devel-2.6.9-67.0.15.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-67.0.15.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-xenU-2.6.9-67.0.15.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-xenU-2.6.9-67.0.15.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-xenU-devel-2.6.9-67.0.15.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-xenU-devel-2.6.9-67.0.15.EL")) flag++;


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
