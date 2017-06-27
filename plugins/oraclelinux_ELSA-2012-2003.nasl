#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2012-2003.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68669);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/12/01 17:16:02 $");

  script_cve_id("CVE-2011-4077", "CVE-2011-4081", "CVE-2011-4132", "CVE-2011-4347", "CVE-2011-4622", "CVE-2012-0038", "CVE-2012-0045", "CVE-2012-0207");
  script_bugtraq_id(50366, 50370, 50663, 50811, 51172, 51343, 51380, 51389);

  script_name(english:"Oracle Linux 5 / 6 : Unbreakable Enterprise kernel (ELSA-2012-2003)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

* CVE-2012-0207: Denial of service bug in IGMP.

The IGMP subsystem's compatibility handling of v2 packets had a bug in
the computation of a delay field which could result in division by
zero (causing a kernel panic).


* CVE-2012-0045: Denial of service in KVM system call emulation.

A bug in the system call emulation for allowed local users on a 32-bit
KVM guest system to cause the guest system to panic.


* CVE-2012-0038: In-memory corruption in XFS ACL processing.

A missing check in xfs_acl_from_disk on the number of XFS ACLs could
result in in-memory corruption and a kernel panic.


* CVE-2011-4622: NULL pointer deference in KVM interval timer emulation.

Starting PIT timers in the absence of irqchip support could cause a
NULL pointer dereference and kernel OOPs.


* CVE-2011-4347: Denial of service in KVM device assignment.

Several bugs that allowed unprivileged users to improperly assign
devices to KVM guests could result in a denial of service.


* CVE-2011-4132: Denial of service in Journaling Block Device layer.

A flaw in the way the Journaling Block Device (JBD) layer handled an
invalid log first block value allowed an attacker to mount a malicious
ext3 or ext4 image that would crash the system.


* CVE-2011-4081: NULL pointer dereference in GHASH cryptographic algorithm.

Nick Bowler reported an issue in the GHASH message digest
algorithm. ghash_update can pass a NULL pointer to gf128mul_4k_lle in some
cases, leading to a NULL pointer dereference (kernel OOPS).


* CVE-2011-4077: Buffer overflow in xfs_readlink.

A flaw in the way the XFS filesystem implementation handled links with
pathnames larger than MAXPATHLEN allowed an attacker to mount a
malicious XFS image that could crash the system or result in privilege
escalation.

[2.6.32-300.11.1.el6uek]
- [fs] xfs: Fix possible memory corruption in xfs_readlink (Carlos 
Maiolino) {CVE-2011-4077}
- [scsi] increase qla2xxx firmware ready time-out (Joe Jin)
- [scsi] qla2xxx: Module parameter to control use of async or sync port 
login (Joe Jin)
- [net] tg3: Fix single-vector MSI-X code (Joe Jin)
- [net] qlge: fix size of external list for TX address descriptors (Joe Jin)
- [net] e1000e: Avoid wrong check on TX hang (Joe Jin)
- crypto: ghash - Avoid NULL pointer dereference if no key is set (Nick 
Bowler) {CVE-2011-4081}
- jbd/jbd2: validate sb->s_first in journal_get_superblock() (Eryu Guan) 
{CVE-2011-4132}
- KVM: Device assignment permission checks (Joe Jin) {CVE-2011-4347}
- KVM: x86: Prevent starting PIT timers in the absence of irqchip 
support (Jan Kiszka) {CVE-2011-4622}
- xfs: validate acl count (Joe Jin) {CVE-2012-0038}
- KVM: x86: fix missing checks in syscall emulation (Joe Jin) 
{CVE-2012-0045}
- KVM: x86: extend 'struct x86_emulate_ops' with 'get_cpuid' (Joe Jin) 
{CVE-2012-0045}
- igmp: Avoid zero delay when receiving odd mixture of IGMP queries (Ben 
Hutchings) {CVE-2012-0207}
- ipv4: correct IGMP behavior on v3 query during v2-compatibility mode 
(David Stevens)
- fuse: fix fuse request unique id (Srinivas Eeda) [orabug 13816349]

[2.6.32-300.10.1.el6uek]
- net: remove extra register in ip_gre (Guru Anbalagane) [Orabug: 13633287]

[2.6.32-300.9.1.el6uek]
- [netdrv] fnic: return zero on fnic_reset() success (Joe Jin)
- [e1000e] Add entropy generation back for network interrupts (John Sobecki)
- [nfs4] LINUX CLIENT TREATS NFS4ERR_GRACE AS A PERMANENT ERROR [orabug 
13476821] (John Sobecki)
- [nfs] NFS CLIENT CONNECTS TO SERVER THEN DISCONNECTS [orabug 13516759] 
(John Sobecki)
- [sunrpc] Add patch for a mount crash in __rpc_create_common [orabug 
13322773] (John Sobecki)

[2.6.32-300.8.1.el6uek]
- SPEC: fix dependency on firmware/mkinitrd (Guru Anbalagane) [orabug 
13637902]
- xfs: fix acl count validation in xfs_acl_from_disk() (Dan Carpenter)
- [SCSI] scsi_dh: check queuedata pointer before proceeding further 
(Moger Babu)
  [orabug 13615419]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-March/002691.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-March/002692.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-300.11.1.el5uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-300.11.1.el5uekdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-300.11.1.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-300.11.1.el6uekdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-300.11.1.el5uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-300.11.1.el5uekdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-300.11.1.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-300.11.1.el6uekdebug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/12");
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
if (rpm_exists(release:"EL5", rpm:"kernel-uek-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-2.6.32-300.11.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-debug-2.6.32-300.11.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-devel-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-debug-devel-2.6.32-300.11.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-devel-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-devel-2.6.32-300.11.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-doc-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-doc-2.6.32-300.11.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-firmware-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-firmware-2.6.32-300.11.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-headers-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-headers-2.6.32-300.11.1.el5uek")) flag++;
if (rpm_check(release:"EL5", reference:"mlnx_en-2.6.32-300.11.1.el5uek-1.5.7-2")) flag++;
if (rpm_check(release:"EL5", reference:"mlnx_en-2.6.32-300.11.1.el5uekdebug-1.5.7-2")) flag++;
if (rpm_check(release:"EL5", reference:"ofa-2.6.32-300.11.1.el5uek-1.5.1-4.0.53")) flag++;
if (rpm_check(release:"EL5", reference:"ofa-2.6.32-300.11.1.el5uekdebug-1.5.1-4.0.53")) flag++;

if (rpm_exists(release:"EL6", rpm:"kernel-uek-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-2.6.32-300.11.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-debug-2.6.32-300.11.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-debug-devel-2.6.32-300.11.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-devel-2.6.32-300.11.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-doc-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-doc-2.6.32-300.11.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-firmware-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-firmware-2.6.32-300.11.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-headers-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-headers-2.6.32-300.11.1.el6uek")) flag++;
if (rpm_check(release:"EL6", reference:"mlnx_en-2.6.32-300.11.1.el6uek-1.5.7-0.1")) flag++;
if (rpm_check(release:"EL6", reference:"mlnx_en-2.6.32-300.11.1.el6uekdebug-1.5.7-0.1")) flag++;
if (rpm_check(release:"EL6", reference:"ofa-2.6.32-300.11.1.el6uek-1.5.1-4.0.47")) flag++;
if (rpm_check(release:"EL6", reference:"ofa-2.6.32-300.11.1.el6uekdebug-1.5.1-4.0.47")) flag++;


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
