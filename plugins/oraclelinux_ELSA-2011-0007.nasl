#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0007 and 
# Oracle Linux Security Advisory ELSA-2011-0007 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68177);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/20 14:21:43 $");

  script_cve_id("CVE-2010-2492", "CVE-2010-3067", "CVE-2010-3078", "CVE-2010-3080", "CVE-2010-3298", "CVE-2010-3477", "CVE-2010-3861", "CVE-2010-3865", "CVE-2010-3874", "CVE-2010-3876", "CVE-2010-3880", "CVE-2010-4072", "CVE-2010-4073", "CVE-2010-4074", "CVE-2010-4075", "CVE-2010-4077", "CVE-2010-4079", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4082", "CVE-2010-4083", "CVE-2010-4158", "CVE-2010-4160", "CVE-2010-4162", "CVE-2010-4163", "CVE-2010-4242", "CVE-2010-4248", "CVE-2010-4249", "CVE-2010-4263", "CVE-2010-4525", "CVE-2010-4668");
  script_bugtraq_id(42237, 42529, 43022, 43062, 43226, 43353, 43806, 43809, 43817, 44427, 44549, 44630, 44661, 44665, 44758, 44762, 44793, 45014, 45028, 45037, 45054, 45058, 45059, 45062, 45063, 45073, 45074, 45208, 45660, 45676);
  script_osvdb_id(67881, 67893, 68177, 69522, 69788, 70375, 70379, 70483);
  script_xref(name:"RHSA", value:"2011:0007");

  script_name(english:"Oracle Linux 6 : kernel (ELSA-2011-0007)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0007 :

Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

* Buffer overflow in eCryptfs. When /dev/ecryptfs has world-writable
permissions (which it does not, by default, on Red Hat Enterprise
Linux 6), a local, unprivileged user could use this flaw to cause a
denial of service or possibly escalate their privileges.
(CVE-2010-2492, Important)

* Integer overflow in the RDS protocol implementation could allow a
local, unprivileged user to cause a denial of service or escalate
their privileges. (CVE-2010-3865, Important)

* Missing boundary checks in the PPP over L2TP sockets implementation
could allow a local, unprivileged user to cause a denial of service or
escalate their privileges. (CVE-2010-4160, Important)

* NULL pointer dereference in the igb driver. If both Single Root I/O
Virtualization (SR-IOV) and promiscuous mode were enabled on an
interface using igb, it could result in a denial of service when a
tagged VLAN packet is received on that interface. (CVE-2010-4263,
Important)

* Missing initialization flaw in the XFS file system implementation,
and in the network traffic policing implementation, could allow a
local, unprivileged user to cause an information leak. (CVE-2010-3078,
CVE-2010-3477, Moderate)

* NULL pointer dereference in the Open Sound System compatible
sequencer driver could allow a local, unprivileged user with access to
/dev/sequencer to cause a denial of service. /dev/sequencer is only
accessible to root and users in the audio group by default.
(CVE-2010-3080, Moderate)

* Flaw in the ethtool IOCTL handler could allow a local user to cause
an information leak. (CVE-2010-3861, Moderate)

* Flaw in bcm_connect() in the Controller Area Network (CAN) Broadcast
Manager. On 64-bit systems, writing the socket address may overflow
the procname character array. (CVE-2010-3874, Moderate)

* Flaw in the module for monitoring the sockets of INET transport
protocols could allow a local, unprivileged user to cause a denial of
service. (CVE-2010-3880, Moderate)

* Missing boundary checks in the block layer implementation could
allow a local, unprivileged user to cause a denial of service.
(CVE-2010-4162, CVE-2010-4163, CVE-2010-4668, Moderate)

* NULL pointer dereference in the Bluetooth HCI UART driver could
allow a local, unprivileged user to cause a denial of service.
(CVE-2010-4242, Moderate)

* Flaw in the Linux kernel CPU time clocks implementation for the
POSIX clock interface could allow a local, unprivileged user to cause
a denial of service. (CVE-2010-4248, Moderate)

* Flaw in the garbage collector for AF_UNIX sockets could allow a
local, unprivileged user to trigger a denial of service.
(CVE-2010-4249, Moderate)

* Missing upper bound integer check in the AIO implementation could
allow a local, unprivileged user to cause an information leak.
(CVE-2010-3067, Low)

* Missing initialization flaws could lead to information leaks.
(CVE-2010-3298, CVE-2010-3876, CVE-2010-4072, CVE-2010-4073,
CVE-2010-4074, CVE-2010-4075, CVE-2010-4077, CVE-2010-4079,
CVE-2010-4080, CVE-2010-4081, CVE-2010-4082, CVE-2010-4083,
CVE-2010-4158, Low)

* Missing initialization flaw in KVM could allow a privileged host
user with access to /dev/kvm to cause an information leak.
(CVE-2010-4525, Low)

Red Hat would like to thank Andre Osterhues for reporting
CVE-2010-2492; Thomas Pollet for reporting CVE-2010-3865; Dan
Rosenberg for reporting CVE-2010-4160, CVE-2010-3078, CVE-2010-3874,
CVE-2010-4162, CVE-2010-4163, CVE-2010-3298, CVE-2010-4073,
CVE-2010-4074, CVE-2010-4075, CVE-2010-4077, CVE-2010-4079,
CVE-2010-4080, CVE-2010-4081, CVE-2010-4082, CVE-2010-4083, and
CVE-2010-4158; Kosuke Tatsukawa for reporting CVE-2010-4263; Tavis
Ormandy for reporting CVE-2010-3080 and CVE-2010-3067; Kees Cook for
reporting CVE-2010-3861 and CVE-2010-4072; Nelson Elhage for reporting
CVE-2010-3880; Alan Cox for reporting CVE-2010-4242; Vegard Nossum for
reporting CVE-2010-4249; Vasiliy Kulikov for reporting CVE-2010-3876;
and Stephan Mueller of atsec information security for reporting
CVE-2010-4525."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-March/002007.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_exists(release:"EL6", rpm:"kernel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-2.6.32-71.14.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-debug-2.6.32") && rpm_check(release:"EL6", reference:"kernel-debug-2.6.32-71.14.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-debug-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-debug-devel-2.6.32-71.14.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-devel-2.6.32-71.14.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-doc-2.6.32") && rpm_check(release:"EL6", reference:"kernel-doc-2.6.32-71.14.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-firmware-2.6.32") && rpm_check(release:"EL6", reference:"kernel-firmware-2.6.32-71.14.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-headers-2.6.32") && rpm_check(release:"EL6", reference:"kernel-headers-2.6.32-71.14.1.el6")) flag++;


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
