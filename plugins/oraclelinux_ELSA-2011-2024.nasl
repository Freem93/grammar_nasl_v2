#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2011-2024.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68420);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 17:07:14 $");

  script_cve_id("CVE-2011-1767", "CVE-2011-1768", "CVE-2011-2213");

  script_name(english:"Oracle Linux 6 : Unbreakable Enterprise kernel (ELSA-2011-2024)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

[2.6.32-200.16.1.el6uek]
- Revert change to restore DEFAULTKERNEL

[2.6.32-200.15.1.el6uek]
- Add -u parameter to kernel_variant_post to make it work
   properly for uek [orabug 12819958]

[2.6.32-200.14.1.el6uek]
- Restore DEFAULTKERNEL value to 'kernel-uek' [orabug 12819958]

[2.6.32-200.13.1.el6uek]
- make default kernel kernel-uek (Kevin Lyons) [orabug 12803424]

[2.6.32-200.12.1.el6uek]
- SCSI: Fix oops dereferencing queue (Martin K. Petersen) [orabug 12741636]

[2.6.32-200.11.1.el6uek]
- inet_diag: fix inet_diag_bc_audit() (Eric Dumazet) [CVE-2011-2213]

[2.6.32-200.10.8.el6uek]
- block: export blk_{get,put}_queue() (Jens Axboe)
- [SCSI] Fix oops caused by queue refcounting failure (James Bottomley)
- [dm-mpath] maintain reference count for underlying devices (Martin K. 
Petersen)

[2.6.32-200.10.7.el6uek]
- [net] gre: fix netns vs proto registration ordering {CVE-2011-1767}
- [net] tunnels: fix netns vs proto registration ordering {CVE-2011-1768}
- [rps] don't free rx_queue until netdevice is freed (Dave Kleikamp) 
[orabug 11071685]

[2.6.32-200.10.6.el6uek]
- Add entropy generation to nics (John Sobecki) [10622900]
- [SCSI] compat_ioct: fix bsg SG_IO [orabug 12732464]
- ipc/sem.c: error path in try_atomic_semop() left spinlock locked

[2.6.32-200.10.5.el6uek]
- update kabi

[2.6.32-200.10.4.el6uek]
- block: Fix double free in blk_integrity_unregister  [orabug 12707880]
- block: Make the integrity mapped property a bio flag [orabug 12707880]
- dm mpath: do not fail paths after integrity errors [orabug 12707880]
- dm ioctl: refactor dm_table_complete   [orabug 12707880]
- block: Require subsystems to explicitly allocate bio_set integrity 
mempool [orabug 12707880]
- dm: improve block integrity support [orabug 12707880]
- sd: Update protection mode strings [orabug 12707880]
- [SCSI] fix propogation of integrity errors [orabug 12707880]
- [SCSI] modify change_queue_depth to take in reason why it is being 
called [orabug 12707880]
- [SCSI] scsi error: have scsi-ml call change_queue_depth to handle 
QUEUE_FULL [orabug 12707880]
- [SCSI] add queue_depth ramp up code [orabug 12707880]
- [SCSI] scsi_dh: Change the scsidh_activate interface to be 
asynchronous [orabug 12707880]
- [SCSI] add queue_depth ramp up code [orabug 12707880]
- [SCSI] scsi_dh: Change the scsidh_activate interface to be 
asynchronous [orabug 12707880]
- SCSI: Updated RDAC device handler [orabug 12707880]
- [SCSI] scsi_dh: propagate SCSI device deletion [orabug 12707880]
- [SCSI] scsi_dh: fix reference counting in scsi_dh_activate error path 
[orabug 12707880]
- qla2xxx: Driver update from QLogic [orabug 12707880]
- lpfc 8.3.5.44 driver update from Emulex  [orabug 12707880]
- Add Hydra (hxge) support [orabug 12314121]
- update hxge to 1.3.1 [orabug 12314121]
- Hide mwait, TSC invariance and MTRR capability in published CPUID

[2.6.32-200.10.3.el6uek]
- [config] Revert 'Add some usb devices supported'
- [config] make all usb drivers part of the kernel.
- [fs] NFS: Don't SIGBUS if nfs_vm_page_mkwrite races with a cache
   invalidation [orabug 10435482]

[2.6.32-200.10.2.el6uek]
- [config] Add some usb devices supported.

[2.6.32-200.10.1.el6uek]
- update kabi changes and revision to -200 series"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-August/002303.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-200.16.1.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-200.16.1.el6uekdebug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/24");
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
if (rpm_exists(release:"EL6", rpm:"kernel-uek-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-2.6.32-200.16.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-debug-2.6.32-200.16.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-debug-devel-2.6.32-200.16.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-devel-2.6.32-200.16.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-doc-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-doc-2.6.32-200.16.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-firmware-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-firmware-2.6.32-200.16.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-headers-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-headers-2.6.32-200.16.1.el6uek")) flag++;
if (rpm_check(release:"EL6", reference:"ofa-2.6.32-200.16.1.el6uek-1.5.1-4.0.47")) flag++;
if (rpm_check(release:"EL6", reference:"ofa-2.6.32-200.16.1.el6uekdebug-1.5.1-4.0.47")) flag++;


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
