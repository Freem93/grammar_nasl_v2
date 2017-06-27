#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:1197 and 
# Oracle Linux Security Advisory ELSA-2011-1197 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68333);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:58:00 $");

  script_cve_id("CVE-2011-2511");
  script_bugtraq_id(48478);
  script_osvdb_id(73668);
  script_xref(name:"RHSA", value:"2011:1197");

  script_name(english:"Oracle Linux 6 : libvirt (ELSA-2011-1197)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:1197 :

Updated libvirt packages that fix one security issue and several bugs
are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The libvirt library is a C API for managing and interacting with the
virtualization capabilities of Linux and other operating systems. In
addition, libvirt provides tools for remotely managing virtualized
systems.

An integer overflow flaw was found in libvirtd's RPC call handling. An
attacker able to establish read-only connections to libvirtd could
trigger this flaw by calling virDomainGetVcpus() with specially
crafted parameters, causing libvirtd to crash. (CVE-2011-2511)

This update also fixes the following bugs :

* Previously, when the 'virsh vol-create-from' command was run on an
LVM (Logical Volume Manager) storage pool, performance of the command
was very low and the operation consumed an excessive amount of time.
This bug has been fixed in the virStorageVolCreateXMLFrom() function,
and the performance problem of the command no longer occurs.

* Due to a regression, libvirt used undocumented command line options,
instead of the recommended ones. Consequently, the qemu-img utility
used an invalid argument while creating an encrypted volume, and the
process eventually failed. With this update, the bug in the backing
format of the storage back end has been fixed, and encrypted volumes
can now be created as expected. (BZ#726617)

* Due to a bug in the qemuAuditDisk() function, hot unplug failures
were never audited, and a hot unplug success was audited as a failure.
This bug has been fixed, and auditing of disk hot unplug operations
now works as expected. (BZ#728516)

* Previously, when a debug process was being activated, the act of
preparing a debug message ended up with dereferencing a UUID
(universally unique identifier) prior to the NULL argument check.
Consequently, an API running the debug process sometimes terminated
with a segmentation fault. With this update, a patch has been provided
to address this issue, and the crashes no longer occur in the
described scenario. (BZ#728546)

* The libvirt library uses the 'boot=on' option to mark which disk is
bootable but it only uses that option if Qemu advertises its support.
The qemu-kvm utility in Red Hat Enterprise Linux 6.1 removed support
for that option and libvirt could not use it. As a consequence, when
an IDE disk was added as the second storage with a virtio disk being
set up as the first one by default, the operating system tried to boot
from the IDE disk rather than the virtio disk and either failed to
boot with the 'No bootable disk' error message returned, or the system
booted whatever operating system was on the IDE disk. With this
update, the boot configuration is translated into bootindex, which
provides control over which device is used for booting a guest
operating system, thus fixing this bug.

All users of libvirt are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing the updated packages, libvirtd must be restarted ('service
libvirtd restart') for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-August/002301.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvirt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-python");
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
if (rpm_check(release:"EL6", reference:"libvirt-0.8.7-18.0.1.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"libvirt-client-0.8.7-18.0.1.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"libvirt-devel-0.8.7-18.0.1.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"libvirt-python-0.8.7-18.0.1.el6_1.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-client / libvirt-devel / libvirt-python");
}
