#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:1350 and 
# Oracle Linux Security Advisory ELSA-2011-1350 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68364);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 16:58:00 $");

  script_cve_id("CVE-2011-1160", "CVE-2011-1745", "CVE-2011-1746", "CVE-2011-1833", "CVE-2011-2022", "CVE-2011-2484", "CVE-2011-2496", "CVE-2011-2521", "CVE-2011-2723", "CVE-2011-2898", "CVE-2011-2918");
  script_bugtraq_id(46866, 47321, 47534, 47535, 47843, 48383, 48580, 48802, 48929, 48986, 49108, 49152);
  script_xref(name:"RHSA", value:"2011:1350");

  script_name(english:"Oracle Linux 6 : kernel (ELSA-2011-1350)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:1350 :

Updated kernel packages that fix several security issues, various
bugs, and add one enhancement are now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* Flaws in the AGPGART driver implementation when handling certain
IOCTL commands could allow a local user to cause a denial of service
or escalate their privileges. (CVE-2011-1745, CVE-2011-2022,
Important)

* An integer overflow flaw in agp_allocate_memory() could allow a
local user to cause a denial of service or escalate their privileges.
(CVE-2011-1746, Important)

* A race condition flaw was found in the Linux kernel's eCryptfs
implementation. A local attacker could use the mount.ecryptfs_private
utility to mount (and then access) a directory they would otherwise
not have access to. Note: To correct this issue, the RHSA-2011:1241
ecryptfs-utils update, which provides the user-space part of the fix,
must also be installed. (CVE-2011-1833, Moderate)

* A denial of service flaw was found in the way the taskstats
subsystem handled the registration of process exit handlers. A local,
unprivileged user could register an unlimited amount of these
handlers, leading to excessive CPU time and memory use.
(CVE-2011-2484, Moderate)

* A flaw was found in the way mapping expansions were handled. A
local, unprivileged user could use this flaw to cause a wrapping
condition, triggering a denial of service. (CVE-2011-2496, Moderate)

* A flaw was found in the Linux kernel's Performance Events
implementation. It could falsely lead the NMI (Non-Maskable Interrupt)
Watchdog to detect a lockup and panic the system. A local,
unprivileged user could use this flaw to cause a denial of service
(kernel panic) using the perf tool. (CVE-2011-2521, Moderate)

* A flaw in skb_gro_header_slow() in the Linux kernel could lead to
GRO (Generic Receive Offload) fields being left in an inconsistent
state. An attacker on the local network could use this flaw to trigger
a denial of service. GRO is enabled by default in all network drivers
that support it. (CVE-2011-2723, Moderate)

* A flaw was found in the way the Linux kernel's Performance Events
implementation handled PERF_COUNT_SW_CPU_CLOCK counter overflow. A
local, unprivileged user could use this flaw to cause a denial of
service. (CVE-2011-2918, Moderate)

* A flaw was found in the Linux kernel's Trusted Platform Module (TPM)
implementation. A local, unprivileged user could use this flaw to leak
information to user-space. (CVE-2011-1160, Low)

* Flaws were found in the tpacket_rcv() and packet_recvmsg() functions
in the Linux kernel. A local, unprivileged user could use these flaws
to leak information to user-space. (CVE-2011-2898, Low)

Red Hat would like to thank Vasiliy Kulikov of Openwall for reporting
CVE-2011-1745, CVE-2011-2022, CVE-2011-1746, and CVE-2011-2484; the
Ubuntu Security Team for reporting CVE-2011-1833; Robert Swiecki for
reporting CVE-2011-2496; Li Yu for reporting CVE-2011-2521; Brent
Meshier for reporting CVE-2011-2723; and Peter Huewe for reporting
CVE-2011-1160. The Ubuntu Security Team acknowledges Vasiliy Kulikov
of Openwall and Dan Rosenberg as the original reporters of
CVE-2011-1833.

This update also fixes various bugs and adds one enhancement.
Documentation for these changes will be available shortly from the
Technical Notes document linked to in the References section.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues, and fix the bugs and add
the enhancement noted in the Technical Notes. The system must be
rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-October/002396.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/10");
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
if (rpm_exists(release:"EL6", rpm:"kernel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-2.6.32-131.17.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-debug-2.6.32") && rpm_check(release:"EL6", reference:"kernel-debug-2.6.32-131.17.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-debug-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-debug-devel-2.6.32-131.17.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-devel-2.6.32-131.17.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-doc-2.6.32") && rpm_check(release:"EL6", reference:"kernel-doc-2.6.32-131.17.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-firmware-2.6.32") && rpm_check(release:"EL6", reference:"kernel-firmware-2.6.32-131.17.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-headers-2.6.32") && rpm_check(release:"EL6", reference:"kernel-headers-2.6.32-131.17.1.el6")) flag++;


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
