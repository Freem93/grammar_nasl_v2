#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:1189 and 
# Oracle Linux Security Advisory ELSA-2011-1189 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68331);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/20 14:21:43 $");

  script_cve_id("CVE-2011-1182", "CVE-2011-1576", "CVE-2011-1593", "CVE-2011-1776", "CVE-2011-1898", "CVE-2011-2183", "CVE-2011-2213", "CVE-2011-2491", "CVE-2011-2492", "CVE-2011-2495", "CVE-2011-2497", "CVE-2011-2517", "CVE-2011-2689", "CVE-2011-2695");
  script_bugtraq_id(47003, 47497, 47796, 48333, 48441, 48472, 48515, 48538, 48677, 48697, 48907, 49141);
  script_xref(name:"RHSA", value:"2011:1189");

  script_name(english:"Oracle Linux 6 : kernel (ELSA-2011-1189)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:1189 :

Updated kernel packages that fix several security issues, various
bugs, and add two enhancements are now available for Red Hat
Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Security issues :

* Using PCI passthrough without interrupt remapping support allowed
KVM guests to generate MSI interrupts and thus potentially inject
traps. A privileged guest user could use this flaw to crash the host
or possibly escalate their privileges on the host. The fix for this
issue can prevent PCI passthrough working and guests starting. Refer
to Red Hat Bugzilla bug 715555 for details. (CVE-2011-1898, Important)

* Flaw in the client-side NLM implementation could allow a local,
unprivileged user to cause a denial of service. (CVE-2011-2491,
Important)

* Integer underflow in the Bluetooth implementation could allow a
remote attacker to cause a denial of service or escalate their
privileges by sending a specially crafted request to a target system
via Bluetooth. (CVE-2011-2497, Important)

* Buffer overflows in the netlink-based wireless configuration
interface implementation could allow a local user, who has the
CAP_NET_ADMIN capability, to cause a denial of service or escalate
their privileges on systems that have an active wireless interface.
(CVE-2011-2517, Important)

* Flaw in the way the maximum file offset was handled for ext4 file
systems could allow a local, unprivileged user to cause a denial of
service. (CVE-2011-2695, Important)

* Flaw allowed napi_reuse_skb() to be called on VLAN packets. An
attacker on the local network could use this flaw to send crafted
packets to a target, possibly causing a denial of service.
(CVE-2011-1576, Moderate)

* Integer signedness error in next_pidmap() could allow a local,
unprivileged user to cause a denial of service. (CVE-2011-1593,
Moderate)

* Race condition in the memory merging support (KSM) could allow a
local, unprivileged user to cause a denial of service. KSM is off by
default, but on systems running VDSM, or on KVM hosts, it is likely
turned on by the ksm/ksmtuned services. (CVE-2011-2183, Moderate)

* Flaw in inet_diag_bc_audit() could allow a local, unprivileged user
to cause a denial of service. (CVE-2011-2213, Moderate)

* Flaw in the way space was allocated in the Global File System 2
(GFS2) implementation. If the file system was almost full, and a
local, unprivileged user made an fallocate() request, it could result
in a denial of service. Setting quotas to prevent users from using all
available disk space would prevent exploitation of this flaw.
(CVE-2011-2689, Moderate)

* Local, unprivileged users could send signals via the sigqueueinfo
system call, with si_code set to SI_TKILL and with spoofed process and
user IDs, to other processes. This flaw does not allow existing
permission checks to be bypassed; signals can only be sent if your
privileges allow you to already do so. (CVE-2011-1182, Low)

* Heap overflow in the EFI GUID Partition Table (GPT) implementation
could allow a local attacker to cause a denial of service by mounting
a disk containing crafted partition tables. (CVE-2011-1776, Low)

* Structure padding in two structures in the Bluetooth implementation
was not initialized properly before being copied to user-space,
possibly allowing local, unprivileged users to leak kernel stack
memory to user-space. (CVE-2011-2492, Low)

* /proc/[PID]/io is world-readable by default. Previously, these files
could be read without any further restrictions. A local, unprivileged
user could read these files, belonging to other, possibly privileged
processes to gather confidential information, such as the length of a
password used in a process. (CVE-2011-2495, Low)

Red Hat would like to thank Vasily Averin for reporting CVE-2011-2491;
Dan Rosenberg for reporting CVE-2011-2497 and CVE-2011-2213; Ryan
Sweat for reporting CVE-2011-1576; Robert Swiecki for reporting
CVE-2011-1593; Andrea Righi for reporting CVE-2011-2183; Julien Tinnes
of the Google Security Team for reporting CVE-2011-1182; Timo Warns
for reporting CVE-2011-1776; Marek Kroemeke and Filip Palian for
reporting CVE-2011-2492; and Vasiliy Kulikov of Openwall for reporting
CVE-2011-2495."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-August/002307.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/26");
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
if (rpm_exists(release:"EL6", rpm:"kernel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-2.6.32-131.12.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-debug-2.6.32") && rpm_check(release:"EL6", reference:"kernel-debug-2.6.32-131.12.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-debug-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-debug-devel-2.6.32-131.12.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-devel-2.6.32-131.12.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-doc-2.6.32") && rpm_check(release:"EL6", reference:"kernel-doc-2.6.32-131.12.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-firmware-2.6.32") && rpm_check(release:"EL6", reference:"kernel-firmware-2.6.32-131.12.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-headers-2.6.32") && rpm_check(release:"EL6", reference:"kernel-headers-2.6.32-131.12.1.el6")) flag++;


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
