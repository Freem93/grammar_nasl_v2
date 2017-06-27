#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(82257);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/26 13:38:48 $");

  script_cve_id("CVE-2014-8136", "CVE-2015-0236");

  script_name(english:"Scientific Linux Security Update : libvirt on SL7.x x86_64");
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
"It was found that QEMU's qemuDomainMigratePerform() and
qemuDomainMigrateFinish2() functions did not correctly perform a
domain unlock on a failed ACL check. A remote attacker able to
establish a connection to libvirtd could use this flaw to lock a
domain of a more privileged user, causing a denial of service.
(CVE-2014-8136)

It was discovered that the virDomainSnapshotGetXMLDesc() and
virDomainSaveImageGetXMLDesc() functions did not sufficiently limit
the usage of the VIR_DOMAIN_XML_SECURE flag when fine-grained ACLs
were enabled. A remote attacker able to establish a connection to
libvirtd could use this flaw to obtain certain sensitive information
from the domain XML file. (CVE-2015-0236)

Bug fixes :

  - The libvirtd daemon previously attempted to search for
    SELinux contexts even when SELinux was disabled on the
    host. Consequently, libvirtd logged 'Unable to lookup
    SELinux process context' error messages every time a
    client connected to libvirtd and SELinux was disabled.
    libvirtd now verifies whether SELinux is enabled before
    searching for SELinux contexts, and no longer logs the
    error messages on a host with SELinux disabled.

  - The libvirt utility passed incomplete PCI addresses to
    QEMU. Consequently, assigning a PCI device that had a
    PCI address with a non- zero domain to a guest failed.
    Now, libvirt properly passes PCI domain to QEMU when
    assigning PCI devices, which prevents the described
    problem.

  - Because the virDomainSetMaxMemory API did not allow
    changing the current memory in the LXC driver, the
    'virsh setmaxmem' command failed when attempting to set
    the maximum memory to be lower than the current memory.
    Now, 'virsh setmaxmem' sets the current memory to the
    intended value of the maximum memory, which avoids the
    mentioned problem.

  - Attempting to start a non-existent domain caused network
    filters to stay locked for read-only access. Because of
    this, subsequent attempts to gain read-write access to
    network filters triggered a deadlock. Network filters
    are now properly unlocked in the described scenario, and
    the deadlock no longer occurs.

  - If a guest configuration had an active nwfilter using
    the DHCP snooping feature and an attempt was made to
    terminate libvirtd before the associated nwfilter rule
    snooped the guest IP address from DHCP packets, libvirtd
    became unresponsive. This problem has been fixed by
    setting a longer wait time for snooping the guest IP
    address.

Enhancements :

  - A new 'migrate_host' option is now available in
    /etc/libvirt/qemu.conf, which allows users to set a
    custom IP address to be used for incoming migrations.

  - With this update, libvirt is able to create a compressed
    memory-only crash dump of a QEMU domain. This type of
    crash dump is directly readable by the GNU Debugger and
    requires significantly less hard disk space than the
    standard crash dump.

  - Support for reporting the NUMA node distance of the host
    has been added to libvirt. This enhances the current
    libvirt capabilities for reporting NUMA topology of the
    host, and allows for easier optimization of new domains.

  - The XML file of guest and host capabilities generated by
    the 'virsh capabilities' command has been enhanced to
    list the following information, where relevant: the
    interface speed and link status of the host, the PCI
    Express (PCIe) details, the host's hardware support for
    I/O virtualization, and a report on the huge memory
    pages.

These packages also include a number of other bug fixes and
enhancements."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1503&L=scientific-linux-errata&T=0&P=2290
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2989bd57"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-1.2.8-16.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-client-1.2.8-16.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-1.2.8-16.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-config-network-1.2.8-16.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-config-nwfilter-1.2.8-16.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-interface-1.2.8-16.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-lxc-1.2.8-16.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-network-1.2.8-16.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-nodedev-1.2.8-16.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-nwfilter-1.2.8-16.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-qemu-1.2.8-16.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-secret-1.2.8-16.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-1.2.8-16.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-kvm-1.2.8-16.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-lxc-1.2.8-16.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-debuginfo-1.2.8-16.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-devel-1.2.8-16.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-docs-1.2.8-16.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-lock-sanlock-1.2.8-16.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-login-shell-1.2.8-16.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
