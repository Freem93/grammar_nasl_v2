#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0004 and 
# Oracle Linux Security Advisory ELSA-2011-0004 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68176);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 16:57:58 $");

  script_cve_id("CVE-2010-3432", "CVE-2010-3442", "CVE-2010-3699", "CVE-2010-3858", "CVE-2010-3859", "CVE-2010-3865", "CVE-2010-3876", "CVE-2010-3880", "CVE-2010-4083", "CVE-2010-4157", "CVE-2010-4161", "CVE-2010-4242", "CVE-2010-4247", "CVE-2010-4248");
  script_bugtraq_id(43480, 43787, 43809, 44301, 44354, 44549, 44630, 44648, 44665, 45014, 45028, 45029, 45039, 45064);
  script_osvdb_id(69013, 69424, 69469, 69551, 69788, 70226, 70264, 70375, 70379, 70380);
  script_xref(name:"RHSA", value:"2011:0004");

  script_name(english:"Oracle Linux 5 : kernel (ELSA-2011-0004)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0004 :

Updated kernel packages that fix multiple security issues, several
bugs, and add an enhancement are now available for Red Hat Enterprise
Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* A flaw was found in sctp_packet_config() in the Linux kernel's
Stream Control Transmission Protocol (SCTP) implementation. A remote
attacker could use this flaw to cause a denial of service.
(CVE-2010-3432, Important)

* A missing integer overflow check was found in snd_ctl_new() in the
Linux kernel's sound subsystem. A local, unprivileged user on a 32-bit
system could use this flaw to cause a denial of service or escalate
their privileges. (CVE-2010-3442, Important)

* A heap overflow flaw in the Linux kernel's Transparent Inter-Process
Communication protocol (TIPC) implementation could allow a local,
unprivileged user to escalate their privileges. (CVE-2010-3859,
Important)

* An integer overflow flaw was found in the Linux kernel's Reliable
Datagram Sockets (RDS) protocol implementation. A local, unprivileged
user could use this flaw to cause a denial of service or escalate
their privileges. (CVE-2010-3865, Important)

* A flaw was found in the Xenbus code for the unified block-device I/O
interface back end. A privileged guest user could use this flaw to
cause a denial of service on the host system running the Xen
hypervisor. (CVE-2010-3699, Moderate)

* Missing sanity checks were found in setup_arg_pages() in the Linux
kernel. When making the size of the argument and environment area on
the stack very large, it could trigger a BUG_ON(), resulting in a
local denial of service. (CVE-2010-3858, Moderate)

* A flaw was found in inet_csk_diag_dump() in the Linux kernel's
module for monitoring the sockets of INET transport protocols. By
sending a netlink message with certain bytecode, a local, unprivileged
user could cause a denial of service. (CVE-2010-3880, Moderate)

* Missing sanity checks were found in gdth_ioctl_alloc() in the gdth
driver in the Linux kernel. A local user with access to '/dev/gdth' on
a 64-bit system could use this flaw to cause a denial of service or
escalate their privileges. (CVE-2010-4157, Moderate)

* The fix for Red Hat Bugzilla bug 484590 as provided in
RHSA-2009:1243 introduced a regression. A local, unprivileged user
could use this flaw to cause a denial of service. (CVE-2010-4161,
Moderate)

* A NULL pointer dereference flaw was found in the Bluetooth HCI UART
driver in the Linux kernel. A local, unprivileged user could use this
flaw to cause a denial of service. (CVE-2010-4242, Moderate)

* It was found that a malicious guest running on the Xen hypervisor
could place invalid data in the memory that the guest shared with the
blkback and blktap back-end drivers, resulting in a denial of service
on the host system. (CVE-2010-4247, Moderate)

* A flaw was found in the Linux kernel's CPU time clocks
implementation for the POSIX clock interface. A local, unprivileged
user could use this flaw to cause a denial of service. (CVE-2010-4248,
Moderate)

* Missing initialization flaws in the Linux kernel could lead to
information leaks. (CVE-2010-3876, CVE-2010-4083, Low)

Red Hat would like to thank Dan Rosenberg for reporting CVE-2010-3442,
CVE-2010-4161, and CVE-2010-4083; Thomas Pollet for reporting
CVE-2010-3865; Brad Spengler for reporting CVE-2010-3858; Nelson
Elhage for reporting CVE-2010-3880; Alan Cox for reporting
CVE-2010-4242; and Vasiliy Kulikov for reporting CVE-2010-3876.

This update also fixes several bugs and adds an enhancement.
Documentation for the bug fixes and the enhancement will be available
shortly from the Technical Notes document, linked to in the References
section.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues, and fix the bugs and add
the enhancement noted in the Technical Notes. The system must be
rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-January/001781.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_exists(release:"EL5", rpm:"kernel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-2.6.18-194.32.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-PAE-2.6.18") && rpm_check(release:"EL5", cpu:"i386", reference:"kernel-PAE-2.6.18-194.32.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-PAE-devel-2.6.18") && rpm_check(release:"EL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-194.32.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-debug-2.6.18") && rpm_check(release:"EL5", reference:"kernel-debug-2.6.18-194.32.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-debug-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-debug-devel-2.6.18-194.32.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-devel-2.6.18-194.32.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-doc-2.6.18") && rpm_check(release:"EL5", reference:"kernel-doc-2.6.18-194.32.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-headers-2.6.18") && rpm_check(release:"EL5", reference:"kernel-headers-2.6.18-194.32.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-xen-2.6.18") && rpm_check(release:"EL5", reference:"kernel-xen-2.6.18-194.32.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-xen-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-xen-devel-2.6.18-194.32.1.0.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
