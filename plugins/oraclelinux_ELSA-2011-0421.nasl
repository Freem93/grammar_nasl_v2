#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0421 and 
# Oracle Linux Security Advisory ELSA-2011-0421 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68247);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 16:57:59 $");

  script_cve_id("CVE-2010-3296", "CVE-2010-4346", "CVE-2010-4526", "CVE-2010-4648", "CVE-2010-4655", "CVE-2010-4656", "CVE-2011-0521", "CVE-2011-0695", "CVE-2011-0710", "CVE-2011-0716", "CVE-2011-1478");
  script_bugtraq_id(43221, 45323, 45661, 45972, 45986, 46069, 46322, 46421, 46433, 46839, 47056);
  script_xref(name:"RHSA", value:"2011:0421");

  script_name(english:"Oracle Linux 6 : kernel (ELSA-2011-0421)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0421 :

Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* A flaw was found in the sctp_icmp_proto_unreachable() function in
the Linux kernel's Stream Control Transmission Protocol (SCTP)
implementation. A remote attacker could use this flaw to cause a
denial of service. (CVE-2010-4526, Important)

* A missing boundary check was found in the dvb_ca_ioctl() function in
the Linux kernel's av7110 module. On systems that use old DVB cards
that require the av7110 module, a local, unprivileged user could use
this flaw to cause a denial of service or escalate their privileges.
(CVE-2011-0521, Important)

* A race condition was found in the way the Linux kernel's InfiniBand
implementation set up new connections. This could allow a remote user
to cause a denial of service. (CVE-2011-0695, Important)

* A heap overflow flaw in the iowarrior_write() function could allow a
user with access to an IO-Warrior USB device, that supports more than
8 bytes per report, to cause a denial of service or escalate their
privileges. (CVE-2010-4656, Moderate)

* A flaw was found in the way the Linux Ethernet bridge implementation
handled certain IGMP (Internet Group Management Protocol) packets. A
local, unprivileged user on a system that has a network interface in
an Ethernet bridge could use this flaw to crash that system.
(CVE-2011-0716, Moderate)

* A NULL pointer dereference flaw was found in the Generic Receive
Offload (GRO) functionality in the Linux kernel's networking
implementation. If both GRO and promiscuous mode were enabled on an
interface in a virtual LAN (VLAN), it could result in a denial of
service when a malformed VLAN frame is received on that interface.
(CVE-2011-1478, Moderate)

* A missing initialization flaw in the Linux kernel could lead to an
information leak. (CVE-2010-3296, Low)

* A missing security check in the Linux kernel's implementation of the
install_special_mapping() function could allow a local, unprivileged
user to bypass the mmap_min_addr protection mechanism. (CVE-2010-4346,
Low)

* A logic error in the orinoco_ioctl_set_auth() function in the Linux
kernel's ORiNOCO wireless extensions support implementation could
render TKIP countermeasures ineffective when it is enabled, as it
enabled the card instead of shutting it down. (CVE-2010-4648, Low)

* A missing initialization flaw was found in the ethtool_get_regs()
function in the Linux kernel's ethtool IOCTL handler. A local user who
has the CAP_NET_ADMIN capability could use this flaw to cause an
information leak. (CVE-2010-4655, Low)

* An information leak was found in the Linux kernel's task_show_regs()
implementation. On IBM S/390 systems, a local, unprivileged user could
use this flaw to read /proc/[PID]/status files, allowing them to
discover the CPU register values of processes. (CVE-2011-0710, Low)

Red Hat would like to thank Jens Kuehnel for reporting CVE-2011-0695;
Kees Cook for reporting CVE-2010-4656 and CVE-2010-4655; Dan Rosenberg
for reporting CVE-2010-3296; and Tavis Ormandy for reporting
CVE-2010-4346.

This update also fixes several bugs. Documentation for these bug fixes
will be available shortly from the Technical Notes document linked to
in the References section.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues, and fix the bugs noted in
the Technical Notes. The system must be rebooted for this update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-April/002065.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/08");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_exists(release:"EL6", rpm:"kernel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-2.6.32-71.24.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-debug-2.6.32") && rpm_check(release:"EL6", reference:"kernel-debug-2.6.32-71.24.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-debug-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-debug-devel-2.6.32-71.24.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-devel-2.6.32-71.24.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-doc-2.6.32") && rpm_check(release:"EL6", reference:"kernel-doc-2.6.32-71.24.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-firmware-2.6.32") && rpm_check(release:"EL6", reference:"kernel-firmware-2.6.32-71.24.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-headers-2.6.32") && rpm_check(release:"EL6", reference:"kernel-headers-2.6.32-71.24.1.el6")) flag++;


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
