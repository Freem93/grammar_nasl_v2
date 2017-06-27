#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61119);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2011-2511");

  script_name(english:"Scientific Linux Security Update : libvirt on SL6.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The libvirt library is a C API for managing and interacting with the
virtualization capabilities of Linux and other operating systems. In
addition, libvirt provides tools for remotely managing virtualized
systems.

An integer overflow flaw was found in libvirtd's RPC call handling. An
attacker able to establish read-only connections to libvirtd could
trigger this flaw by calling virDomainGetVcpus() with specially
crafted parameters, causing libvirtd to crash. (CVE-2011-2511)

This update also fixes the following bugs :

  - Previously, when the 'virsh vol-create-from' command was
    run on an LVM (Logical Volume Manager) storage pool,
    performance of the command was very low and the
    operation consumed an excessive amount of time. This bug
    has been fixed in the virStorageVolCreateXMLFrom()
    function, and the performance problem of the command no
    longer occurs.

  - Due to a regression, libvirt used undocumented command
    line options, instead of the recommended ones.
    Consequently, the qemu-img utility used an invalid
    argument while creating an encrypted volume, and the
    process eventually failed. With this update, the bug in
    the backing format of the storage back end has been
    fixed, and encrypted volumes can now be created as
    expected.

  - Due to a bug in the qemuAuditDisk() function, hot unplug
    failures were never audited, and a hot unplug success
    was audited as a failure. This bug has been fixed, and
    auditing of disk hot unplug operations now works as
    expected.

  - Previously, when a debug process was being activated,
    the act of preparing a debug message ended up with
    dereferencing a UUID (universally unique identifier)
    prior to the NULL argument check. Consequently, an API
    running the debug process sometimes terminated with a
    segmentation fault. With this update, a patch has been
    provided to address this issue, and the crashes no
    longer occur in the described scenario.

  - The libvirt library uses the 'boot=on' option to mark
    which disk is bootable but it only uses that option if
    Qemu advertises its support. The qemu-kvm utility in
    Scientific Linux 6.1 removed support for that option and
    libvirt could not use it. As a consequence, when an IDE
    disk was added as the second storage with a virtio disk
    being set up as the first one by default, the operating
    system tried to boot from the IDE disk rather than the
    virtio disk and either failed to boot with the 'No
    bootable disk' error message returned, or the system
    booted whatever operating system was on the IDE disk.
    With this update, the boot configuration is translated
    into bootindex, which provides control over which device
    is used for booting a guest operating system, thus
    fixing this bug.

All users of libvirt are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing the updated packages, libvirtd must be restarted ('service
libvirtd restart') for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1109&L=scientific-linux-errata&T=0&P=751
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b0f81814"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"libvirt-0.8.7-18.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-client-0.8.7-18.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-debuginfo-0.8.7-18.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-devel-0.8.7-18.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-python-0.8.7-18.el6_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
