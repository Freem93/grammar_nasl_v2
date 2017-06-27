#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1019 and 
# CentOS Errata and Security Advisory 2011:1019 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(56264);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/26 15:53:26 $");

  script_cve_id("CVE-2011-2511");
  script_bugtraq_id(48478);
  script_osvdb_id(73668);
  script_xref(name:"RHSA", value:"2011:1019");

  script_name(english:"CentOS 5 : libvirt (CESA-2011:1019)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libvirt packages that fix one security issue, several bugs and
add various enhancements are now available for Red Hat Enterprise
Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The libvirt library is a C API for managing and interacting with the
virtualization capabilities of Linux and other operating systems.

An integer overflow flaw was found in libvirtd's RPC call handling. An
attacker able to establish read-only connections to libvirtd could
trigger this flaw by calling virDomainGetVcpus() with specially
crafted parameters, causing libvirtd to crash. (CVE-2011-2511)

This update fixes the following bugs :

* libvirt was rebased from version 0.6.3 to version 0.8.2 in Red Hat
Enterprise Linux 5.6. A code audit found a minor API change that
effected error messages seen by libvirt 0.8.2 clients talking to
libvirt 0.7.1 - 0.7.7 (0.7.x) servers. A libvirt 0.7.x server could
send VIR_ERR_BUILD_FIREWALL errors where a libvirt 0.8.2 client
expected VIR_ERR_CONFIG_UNSUPPORTED errors. In other circumstances, a
libvirt 0.8.2 client saw a 'Timed out during operation' message where
it should see an 'Invalid network filter' error. This update adds a
backported patch that allows libvirt 0.8.2 clients to interoperate
with the API as used by libvirt 0.7.x servers, ensuring correct error
messages are sent. (BZ#665075)

* libvirt could crash if the maximum number of open file descriptors
(_SC_OPEN_MAX) grew larger than the FD_SETSIZE value because it
accessed file descriptors outside the bounds of the set. With this
update the maximum number of open file descriptors can no longer grow
larger than the FD_SETSIZE value. (BZ#665549)

* A libvirt race condition was found. An array in the libvirt event
handlers was accessed with a lock temporarily released. In rare cases,
if one thread attempted to access this array but a second thread
reallocated the array before the first thread reacquired a lock, it
could lead to the first thread attempting to access freed memory,
potentially causing libvirt to crash. With this update libvirt no
longer refers to the old array and, consequently, behaves as expected.
(BZ#671569)

* Guests connected to a passthrough NIC would kernel panic if a
system_reset signal was sent through the QEMU monitor. With this
update you can reset such guests as expected. (BZ#689880)

* When using the Xen kernel, the rpmbuild command failed on the
xencapstest test. With this update you can run rpmbuild successfully
when using the Xen kernel. (BZ#690459)

* When a disk was hot unplugged, 'ret >= 0' was passed to the
qemuAuditDisk calls in disk hotunplug operations before ret was, in
fact, set to 0. As well, the error path jumped to the 'cleanup' label
prematurely. As a consequence, hotunplug failures were not audited and
hotunplug successes were audited as failures. This was corrected and
hot unplugging checks now behave as expected. (BZ#710151)

* A conflict existed between filter update locking sequences and
virtual machine startup locking sequences. When a filter update
occurred on one or more virtual machines, a deadlock could
consequently occur if a virtual machine referencing a filter was
started. This update changes and makes more flexible several qemu
locking sequences ensuring this deadlock no longer occurs. (BZ#697749)

* qemudDomainSaveImageStartVM closed some incoming file descriptor
(fd) arguments without informing the caller. The consequent
double-closes could cause Domain restoration failure. This update
alters the qemudDomainSaveImageStartVM signature to prevent the
double-closes. (BZ#681623)

This update also adds the following enhancements :

* The libvirt Xen driver now supports more than one serial port.
(BZ#670789)

* Enabling and disabling the High Precision Event Timer (HPET) in Xen
domains is now possible. (BZ#703193)

All libvirt users should install this update which addresses this
vulnerability, fixes these bugs and adds these enhancements. After
installing the updated packages, libvirtd must be restarted ('service
libvirtd restart') for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017880.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd5803b2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017881.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dd442231"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000078.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6a0b011"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000079.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b43e411f"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"libvirt-0.8.2-22.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libvirt-devel-0.8.2-22.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libvirt-python-0.8.2-22.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
