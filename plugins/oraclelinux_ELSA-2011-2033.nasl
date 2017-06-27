#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2011-2033.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68424);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/12/01 17:07:14 $");

  script_cve_id("CVE-2011-1162", "CVE-2011-1577", "CVE-2011-2494", "CVE-2011-2699", "CVE-2011-2905", "CVE-2011-3188", "CVE-2011-3191", "CVE-2011-3353", "CVE-2011-3359", "CVE-2011-3593", "CVE-2011-4326");

  script_name(english:"Oracle Linux 5 / 6 : Unbreakable Enterprise kernel (ELSA-2011-2033)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

* CVE-2011-1161: Information leak in transmission logic of TPM driver.

A missing buffer size check in tpm_transmit could allow leaking of
potentially sensitive kernel memory.

* CVE-2011-1162: Information leak in TPM driver.

A flaw in the way memory containing security-related data was handled
in tpm_read() could allow a local, unprivileged user to read the
results of a previously run TPM command.  (CVE-2011-1162, Low)

* CVE-2011-2494: Information leak in task/process statistics.

The I/O statistics from the taskstats subsystem could be read without
any restrictions.  A local, unprivileged user could use this flaw to
gather confidential information, such as the length of a password used
in a process.  (CVE-2011-2494, Low)

* CVE-2011-3188: Weak TCP sequence number generation.

The way IPv4 and IPv6 protocol sequence numbers and fragment IDs were
generated could allow a man-in-the-middle attacker to inject packets
and possibly hijack connections.  Protocol sequence numbers and
fragment IDs are now more random. (CVE-2011-3188, Moderate)

* CVE-2011-1577: Missing boundary checks in GPT partition handling.


A heap overflow flaw in the Linux kernel's EFI GUID Partition Table
(GPT) implementation could allow a local attacker to cause a denial
of service by mounting a disk that contains specially crafted
partition tables.  (CVE-2011-1577, Low)

* CVE-2011-3191: Memory corruption in CIFS.

A malicious CIFS server could overflow a signed integer value, causing a
memcpy() to scribble over a large amount of memory.

* CVE-2011-3353: Denial of service in FUSE via FUSE_NOTIFY_INVAL_ENTRY.

A buffer overflow flaw was found in the Linux kernel's FUSE
(Filesystem in Userspace) implementation.  A local user in the fuse
group who has access to mount a FUSE file system could use this flaw
to cause a denial of service.  (CVE-2011-3353, Moderate)

* CVE-2011-4326: Denial of service in IPv6 UDP Fragmentation Offload.

A flaw was found in the way the Linux kernel handled fragmented IPv6
UDP datagrams over the bridge with UDP Fragmentation Offload (UFO)
functionality on.  A remote attacker could use this flaw to cause a
denial of service.  (CVE-2011-4326, Important)

* CVE-2011-3593: Denial of service in VLAN with priority tagged frames.

A flaw was found in the way the Linux kernel handled VLAN 0 frames
with the priority tag set.  When using certain network drivers, an
attacker on the local network could use this flaw to cause a denial of
service.  (CVE-2011-3593, Moderate)

* CVE-2011-2699: Predictable IPv6 fragment identification numbers.

IPv6 fragment identification value generation could allow a remote
attacker to disrupt a target system's networking, preventing
legitimate users from accessing its services.  (CVE-2011-2699,
Important)

kernel-uek:

[2.6.32-200.23.1.el5uek]
- net: Remove atmclip.h to prevent break kabi check.
- KConfig: add CONFIG_UEK5=n to ol6/config-generic

  [2.6.32-200.22.1.el5uek]
- ipv6: make fragment identifications less predictable (Joe Jin) 
{CVE-2011-2699}
- vlan: fix panic when handling priority tagged frames (Joe Jin) 
{CVE-2011-3593}
- ipv6: udp: fix the wrong headroom check (Maxim Uvarov) {CVE-2011-4326}
- b43: allocate receive buffers big enough for max frame len + offset 
(Maxim Uvarov) {CVE-2011-3359}
- fuse: check size of FUSE_NOTIFY_INVAL_ENTRY message (Maxim Uvarov) 
{CVE-2011-3353}
- cifs: fix possible memory corruption in CIFSFindNext (Maxim Uvarov) 
{CVE-2011-3191}
- crypto: md5 - Add export support (Maxim Uvarov) {CVE-2011-2699}
- fs/partitions/efi.c: corrupted GUID partition tables can cause kernel 
oops (Maxim Uvarov) {CVE-2011-1577}
- block: use struct parsed_partitions *state universally in partition 
check code (Maxim Uvarov)
- net: Compute protocol sequence numbers and fragment IDs using MD5. 
(Maxim Uvarov) {CVE-2011-3188}
- crypto: Move md5_transform to lib/md5.c (Maxim Uvarov) {CVE-2011-3188}
- perf tools: do not look at ./config for configuration (Maxim Uvarov) 
{CVE-2011-2905}
- Make TASKSTATS require root access (Maxim Uvarov) {CVE-2011-2494}
- TPM: Zero buffer after copying to userspace (Maxim Uvarov) {CVE-2011-1162}
- TPM: Call tpm_transmit with correct size (Maxim Uvarov){CVE-2011-1161}
- fnic: fix panic while booting in fnic(Xiaowei Hu)
- Revert 'PCI hotplug: acpiphp: set current_state to D0 in 
register_slot' (Guru Anbalagane)
- xen: drop xen_sched_clock in favour of using plain wallclock time 
(Jeremy Fitzhardinge)

[2.6.32-200.21.1.el5uek]
- PCI: Set device power state to PCI_D0 for device without native PM support
   (Ajaykumar Hotchandani) [orabug 13033435]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-November/002477.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-November/002478.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-200.23.1.el5uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-200.23.1.el5uekdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-200.23.1.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-200.23.1.el6uekdebug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/28");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-2.6.32-200.23.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-debug-2.6.32-200.23.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-devel-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-debug-devel-2.6.32-200.23.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-devel-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-devel-2.6.32-200.23.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-doc-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-doc-2.6.32-200.23.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-firmware-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-firmware-2.6.32-200.23.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-headers-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-uek-headers-2.6.32-200.23.1.el5uek")) flag++;
if (rpm_check(release:"EL5", reference:"ofa-2.6.32-200.23.1.el5uek-1.5.1-4.0.53")) flag++;
if (rpm_check(release:"EL5", reference:"ofa-2.6.32-200.23.1.el5uekdebug-1.5.1-4.0.53")) flag++;

if (rpm_exists(release:"EL6", rpm:"kernel-uek-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-2.6.32-200.23.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-debug-2.6.32-200.23.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-debug-devel-2.6.32-200.23.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-devel-2.6.32-200.23.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-doc-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-doc-2.6.32-200.23.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-firmware-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-firmware-2.6.32-200.23.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-headers-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-headers-2.6.32-200.23.1.el6uek")) flag++;
if (rpm_check(release:"EL6", reference:"ofa-2.6.32-200.23.1.el6uek-1.5.1-4.0.47")) flag++;
if (rpm_check(release:"EL6", reference:"ofa-2.6.32-200.23.1.el6uekdebug-1.5.1-4.0.47")) flag++;


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
