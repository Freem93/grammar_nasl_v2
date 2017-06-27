#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61090);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2011-2511");

  script_name(english:"Scientific Linux Security Update : libvirt on SL5.x i386/x86_64");
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
virtualization capabilities of Linux and other operating systems.

An integer overflow flaw was found in libvirtd's RPC call handling. An
attacker able to establish read-only connections to libvirtd could
trigger this flaw by calling virDomainGetVcpus() with specially
crafted parameters, causing libvirtd to crash. (CVE-2011-2511)

This update fixes the following bugs :

  - libvirt was rebased from version 0.6.3 to version 0.8.2
    in Scientific Linux 5.6. A code audit found a minor API
    change that effected error messages seen by libvirt
    0.8.2 clients talking to libvirt 0.7.1 &#150; 0.7.7
    (0.7.x) servers. A libvirt 0.7.x server could send
    VIR_ERR_BUILD_FIREWALL errors where a libvirt 0.8.2
    client expected VIR_ERR_CONFIG_UNSUPPORTED errors. In
    other circumstances, a libvirt 0.8.2 client saw a 'Timed
    out during operation' message where it should see an
    'Invalid network filter' error. This update adds a
    backported patch that allows libvirt 0.8.2 clients to
    interoperate with the API as used by libvirt 0.7.x
    servers, ensuring correct error messages are sent.

  - libvirt could crash if the maximum number of open file
    descriptors (_SC_OPEN_MAX) grew larger than the
    FD_SETSIZE value because it accessed file descriptors
    outside the bounds of the set. With this update the
    maximum number of open file descriptors can no longer
    grow larger than the FD_SETSIZE value.

  - A libvirt race condition was found. An array in the
    libvirt event handlers was accessed with a lock
    temporarily released. In rare cases, if one thread
    attempted to access this array but a second thread
    reallocated the array before the first thread reacquired
    a lock, it could lead to the first thread attempting to
    access freed memory, potentially causing libvirt to
    crash. With this update libvirt no longer refers to the
    old array and, consequently, behaves as expected.

  - Guests connected to a passthrough NIC would kernel panic
    if a system_reset signal was sent through the QEMU
    monitor. With this update you can reset such guests as
    expected.

  - When using the Xen kernel, the rpmbuild command failed
    on the xencapstest test. With this update you can run
    rpmbuild successfully when using the Xen kernel.

  - When a disk was hot unplugged, 'ret >= 0' was passed to
    the qemuAuditDisk calls in disk hotunplug operations
    before ret was, in fact, set to 0. As well, the error
    path jumped to the 'cleanup' label prematurely. As a
    consequence, hotunplug failures were not audited and
    hotunplug successes were audited as failures. This was
    corrected and hot unplugging checks now behave as
    expected.

  - A conflict existed between filter update locking
    sequences and virtual machine startup locking sequences.
    When a filter update occurred on one or more virtual
    machines, a deadlock could consequently occur if a
    virtual machine referencing a filter was started. This
    update changes and makes more flexible several qemu
    locking sequences ensuring this deadlock no longer
    occurs.

  - qemudDomainSaveImageStartVM closed some incoming file
    descriptor (fd) arguments without informing the caller.
    The consequent double-closes could cause Domain
    restoration failure. This update alters the
    qemudDomainSaveImageStartVM signature to prevent the
    double-closes.

This update also adds the following enhancements :

  - The libvirt Xen driver now supports more than one serial
    port.

  - Enabling and disabling the High Precision Event Timer
    (HPET) in Xen domains is now possible.

All libvirt users should install this update which addresses this
vulnerability, fixes these bugs and adds these enhancements. After
installing the updated packages, libvirtd must be restarted ('service
libvirtd restart') for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1108&L=scientific-linux-errata&T=0&P=3827
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?866adf42"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libvirt, libvirt-devel and / or libvirt-python
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/21");
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
if (rpm_check(release:"SL5", reference:"libvirt-0.8.2-22.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libvirt-devel-0.8.2-22.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libvirt-python-0.8.2-22.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
