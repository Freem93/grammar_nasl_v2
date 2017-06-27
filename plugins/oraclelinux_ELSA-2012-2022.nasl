#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2012-2022.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68677);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/12/01 17:16:03 $");

  script_cve_id("CVE-2011-4127", "CVE-2011-4131", "CVE-2012-2384");
  script_bugtraq_id(51176, 53971);

  script_name(english:"Oracle Linux 5 / 6 : Unbreakable Enterprise kernel (ELSA-2012-2022)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

* Avoid bug caused by corrupted Ext4 filesystem.

When mounting an ext4 filesystem, the kernel was not checking for zero
length extents. This would cause a BUG_ON assertion failure in the log.


* NULL pointer dereference in the SCSI subsystem.

A NULL dereference may occur if a SCSI device is physically removed
without being logically removed from the system.

This would lead to a NULL dereference since the revalidation routine
assumed the device is always present while it runs.


* Resource leak in USB networking driver.

The usbnet core incorrectly cleared a pointer to the underlying device
resulting in a resource leak when unlinking requests.


* Inode corruption in XFS inode lookup.

The XFS inode cache did not correctly initialize the inode before
insertion into the cache which could result in corruption when racing
with an inode lookup.


* Kernel crash in SUNRPC cache management.

Many SUNRPC cache implementations would not handle a zero-length
string resulting in a kernel panic.


* Unbalanced locking in VFS non-local alias search.

A code path responsible for finding aliases on a non-local filesystem
did not correctly release a lock resulting in a system hang.


* Memory corruption on nfsd shutdown.

A race condition between closing down a SUNRPC transport and enqueueing
data could result in a use-after-free condition resulting in a
denial-of-service or privilege escalation.


* NULL pointer dereference with misconfigured USB FTDI devices.

A USB FTDI without a manufacturer string would result in a NULL pointer
dereference and kernel crash when the device was plugged in.


* Kernel information leak in X86 ptrace TLS regset.

The TLS lookup could run off the end of the descriptor list reading from
kernel memory.


* Divide-by-zero in NTP.

Integer overflow in NTP when setting the time could result in a
divide-by-zero and kernel panic.


* CVE-2011-4127: KVM privilege escalation through insufficient validation in SG_IO ioctl.

Using the SG_IO IOCTL to issue SCSI requests to partitions or LVM
volumes resulted in the requests being passed to the underlying block
device. If a privileged user only had access to a single partition or
LVM volume, they could use this flaw to bypass those restrictions and
gain read and write access (and be able to issue other SCSI commands)
to the entire block device.

In KVM (Kernel-based Virtual Machine) environments using raw format
virtio disks backed by a partition or LVM volume, a privileged guest
user could bypass intended restrictions and issue read and write
requests (and other SCSI commands) on the host, and possibly access
the data of other guests that reside on the same underlying block
device.


* CVE-2012-2384: Integer overflow in Intel i915 command processing.

An integer overflow in the Intel i915 family display driver could cause memory
corruption on 32-bit systems.


* Correctly merge virtual memory areas when binding.

When mbind() is called for adjacent areas, they are expected to be merged into
a single virtual memory area.


* Small UDP packets dropped on transmission consistently in vmxnet3.

Small (<54 byte) packets will get dropped consistently on transmission due
to an error in the optimization of the code.


* CVE-2011-4131: Kernel crash in NFSv4.

nfs4_getfacl decoding causes a kernel crash when a server returns more
than 2 GETATTR bitmap words in response to the FATTR4_ACL attribute
request."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-July/002896.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-July/002897.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/02");
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
if (rpm_exists(release:"EL5", rpm:"kernel-uek-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-2.6.39-200.24.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-debug-2.6.39-200.24.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-devel-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-debug-devel-2.6.39-200.24.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-devel-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-devel-2.6.39-200.24.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-doc-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-doc-2.6.39-200.24.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-firmware-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-firmware-2.6.39-200.24.1.el5uek")) flag++;

if (rpm_exists(release:"EL6", rpm:"kernel-uek-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-2.6.39-200.24.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-debug-2.6.39-200.24.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-devel-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-debug-devel-2.6.39-200.24.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-devel-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-devel-2.6.39-200.24.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-doc-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-doc-2.6.39-200.24.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-firmware-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-firmware-2.6.39-200.24.1.el6uek")) flag++;


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
