#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:1645 and 
# Oracle Linux Security Advisory ELSA-2013-1645 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(71108);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/12/01 17:25:12 $");

  script_cve_id("CVE-2012-6542", "CVE-2012-6545", "CVE-2013-0343", "CVE-2013-1928", "CVE-2013-1929", "CVE-2013-2164", "CVE-2013-2234", "CVE-2013-2851", "CVE-2013-2888", "CVE-2013-2889", "CVE-2013-2892", "CVE-2013-3231", "CVE-2013-4345", "CVE-2013-4387", "CVE-2013-4591", "CVE-2013-4592");
  script_bugtraq_id(51343, 51389, 51625, 52274, 52533, 52687, 53162, 53165, 53166, 53233, 53414, 53488, 53615, 53668, 53721, 53965, 53971, 54062, 54063, 54279, 54365, 54367, 54702, 54763, 55151, 55361, 55878, 56238, 56346, 56414, 57433, 57838, 57940, 57986, 58088, 58112, 58177, 58200, 58202, 58368, 58381, 58383, 58426, 58427, 58597, 58600, 58604, 58605, 58607, 58795, 58906, 58908, 58977, 58989, 58990, 58991, 58992, 58994, 58996, 59055, 59377, 59383, 59385, 59390, 59549, 59846, 60214, 60324, 60375, 60409, 60410, 60463, 60466, 60715, 60858, 60874, 60893, 60953, 61411, 62042, 62043, 62049, 62696, 62740, 63183, 63790, 63791);
  script_osvdb_id(90811, 90964, 90967, 92021, 92027, 92664, 94033, 94035, 94698, 96766, 96767, 96775, 97888, 98017, 100002, 100003);
  script_xref(name:"RHSA", value:"2013:1645");

  script_name(english:"Oracle Linux 6 : Kernel (ELSA-2013-1645)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:1645 :

Updated kernel packages that fix multiple security issues, address
several hundred bugs, and add numerous enhancements are now available
as part of the ongoing support and maintenance of Red Hat Enterprise
Linux version 6. This is the fifth regular update.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* A flaw was found in the way the Linux kernel's IPv6 implementation
handled certain UDP packets when the UDP Fragmentation Offload (UFO)
feature was enabled. A remote attacker could use this flaw to crash
the system or, potentially, escalate their privileges on the system.
(CVE-2013-4387, Important)

* A flaw was found in the way the Linux kernel handled the creation of
temporary IPv6 addresses. If the IPv6 privacy extension was enabled
(/proc/sys/net/ipv6/conf/eth0/use_tempaddr set to '2'), an attacker on
the local network could disable IPv6 temporary address generation,
leading to a potential information disclosure. (CVE-2013-0343,
Moderate)

* A flaw was found in the way the Linux kernel handled HID (Human
Interface Device) reports with an out-of-bounds Report ID. An attacker
with physical access to the system could use this flaw to crash the
system or, potentially, escalate their privileges on the system.
(CVE-2013-2888, Moderate)

* An off-by-one flaw was found in the way the ANSI CPRNG
implementation in the Linux kernel processed non-block size aligned
requests. This could lead to random numbers being generated with less
bits of entropy than expected when ANSI CPRNG was used.
(CVE-2013-4345, Moderate)

* It was found that the fix for CVE-2012-2375 released via
RHSA-2012:1580 accidentally removed a check for small-sized result
buffers. A local, unprivileged user with access to an NFSv4 mount with
ACL support could use this flaw to crash the system or, potentially,
escalate their privileges on the system . (CVE-2013-4591, Moderate)

* A flaw was found in the way IOMMU memory mappings were handled when
moving memory slots. A malicious user on a KVM host who has the
ability to assign a device to a guest could use this flaw to crash the
host. (CVE-2013-4592, Moderate)

* Heap-based buffer overflow flaws were found in the way the Zeroplus
and Pantherlord/GreenAsia game controllers handled HID reports. An
attacker with physical access to the system could use these flaws to
crash the system or, potentially, escalate their privileges on the
system. (CVE-2013-2889, CVE-2013-2892, Moderate)

* Two information leak flaws were found in the logical link control
(LLC) implementation in the Linux kernel. A local, unprivileged user
could use these flaws to leak kernel stack memory to user space.
(CVE-2012-6542, CVE-2013-3231, Low)

* A heap-based buffer overflow in the way the tg3 Ethernet driver
parsed the vital product data (VPD) of devices could allow an attacker
with physical access to a system to cause a denial of service or,
potentially, escalate their privileges. (CVE-2013-1929, Low)

* Information leak flaws in the Linux kernel could allow a privileged,
local user to leak kernel memory to user space. (CVE-2012-6545,
CVE-2013-1928, CVE-2013-2164, CVE-2013-2234, Low)

* A format string flaw was found in the Linux kernel's block layer. A
privileged, local user could potentially use this flaw to escalate
their privileges to kernel level (ring0). (CVE-2013-2851, Low)

Red Hat would like to thank Stephan Mueller for reporting
CVE-2013-4345, and Kees Cook for reporting CVE-2013-2851.

This update also fixes several hundred bugs and adds enhancements.
Refer to the Red Hat Enterprise Linux 6.5 Release Notes for
information on the most significant of these changes, and the
Technical Notes for further information, both linked to in the
References.

All Red Hat Enterprise Linux 6 users are advised to install these
updated packages, which correct these issues, and fix the bugs and add
the enhancements noted in the Red Hat Enterprise Linux 6.5 Release
Notes and Technical Notes. The system must be rebooted for this update
to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-November/003809.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/27");
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
if (rpm_exists(release:"EL6", rpm:"kernel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-2.6.32-431.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-abi-whitelists-2.6.32") && rpm_check(release:"EL6", reference:"kernel-abi-whitelists-2.6.32-431.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-debug-2.6.32") && rpm_check(release:"EL6", reference:"kernel-debug-2.6.32-431.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-debug-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-debug-devel-2.6.32-431.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-devel-2.6.32-431.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-doc-2.6.32") && rpm_check(release:"EL6", reference:"kernel-doc-2.6.32-431.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-firmware-2.6.32") && rpm_check(release:"EL6", reference:"kernel-firmware-2.6.32-431.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-headers-2.6.32") && rpm_check(release:"EL6", reference:"kernel-headers-2.6.32-431.el6")) flag++;
if (rpm_check(release:"EL6", reference:"perf-2.6.32-431.el6")) flag++;
if (rpm_check(release:"EL6", reference:"python-perf-2.6.32-431.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
