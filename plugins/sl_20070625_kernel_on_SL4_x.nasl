#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60215);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_cve_id("CVE-2006-5158", "CVE-2006-7203", "CVE-2007-0773", "CVE-2007-0958", "CVE-2007-1353", "CVE-2007-2172", "CVE-2007-2525", "CVE-2007-2876", "CVE-2007-3104");

  script_name(english:"Scientific Linux Security Update : kernel on SL4.x i386/x86_64");
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
"These new kernel packages contain fixes for the security issues
described below :

  - a flaw in the connection tracking support for SCTP that
    allowed a remote user to cause a denial of service by
    dereferencing a NULL pointer. (CVE-2007-2876, Important)

  - a flaw in the mount handling routine for 64-bit systems
    that allowed a local user to cause denial of service
    (crash). (CVE-2006-7203, Important)

  - a flaw in the IPv4 forwarding base that allowed a local
    user to cause an out-of-bounds access. (CVE-2007-2172,
    Important)

  - a flaw in the PPP over Ethernet implementation that
    allowed a local user to cause a denial of service
    (memory consumption) by creating a socket using connect
    and then releasing it before the PPPIOCGCHAN ioctl has
    been called. (CVE-2007-2525, Important)

  - a flaw in the fput ioctl handling of 32-bit applications
    running on 64-bit platforms that allowed a local user to
    cause a denial of service (panic). (CVE-2007-0773,
    Important)

  - a flaw in the NFS locking daemon that allowed a local
    user to cause denial of service (deadlock).
    (CVE-2006-5158, Moderate)

  - a flaw in the sysfs_readdir function that allowed a
    local user to cause a denial of service by dereferencing
    a NULL pointer. (CVE-2007-3104, Moderate)

  - a flaw in the core-dump handling that allowed a local
    user to create core dumps from unreadable binaries via
    PT_INTERP. (CVE-2007-0958, Low)

  - a flaw in the Bluetooth subsystem that allowed a local
    user to trigger an information leak. (CVE-2007-1353,
    Low)

In addition, the following bugs were addressed :

  - the NFS could recurse on the same spinlock. Also, NFS,
    under certain conditions, did not completely clean up
    Posix locks on a file close, leading to mount failures.

  - the 32bit compatibility didn't return to userspace
    correct values for the rt_sigtimedwait system call.

  - the count for unused inodes could be incorrect at times,
    resulting in dirty data not being written to disk in a
    timely manner.

  - the cciss driver had an incorrect disk size calculation
    (off-by-one error) which prevented disk dumps.

NOTE1: From The Upstream Vendors release notes 'During PCI probing,
Red Hat Enterprise Linux 4 Update 5 attempts to use information
obtained from MCFG (memory-mapped PCI configuration space). On
AMD-systems, this type of access does not work on some buses, as the
kernel cannot parse the MCFG table.

To work around this, add the parameter pci=conf1 or pci=nommconf on
the kernel boot line in /etc/grub.conf. For example :

title Red Hat Enterprise Linux AS (2.6.9-42.0.2.EL) root (hd0,0)
kernel /vmlinuz-2.6.9-42.0.2.EL ro root=/dev/VolGroup00/LogVol00 rhgb
quiet pci=conf1 initrd /initrd-2.6.9-42.0.2.EL.img

Doing this instructs the kernel to use PCI Conf1 access instead of
MCFG-based access.'

NOTE2: From The Upstream Vendors Knowledge Base 'Why did the ordering
of my NIC devices change in Red Hat Enterprise Linux 4.5?

The 2.6.9-55 version of the Red Hat Enterprise Linux 4 kernel (Update
5) reverts to the 2.4 ordering of network interface cards (NICs) on
certain systems. Note that if the 'HWADDR=MAC ADDRESS' line is present
in the /etc/sysconfig/network-scripts/ifcfg-ethX files, the NIC
ordering will not change.

To restore the original 2.6 ordering, which is different from the 2.4
ordering, boot with the option pci=nobfsort '"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0706&L=scientific-linux-errata&T=0&P=4280
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b83efce6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"kernel-2.6.9-55.0.2.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-devel-2.6.9-55.0.2.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-doc-2.6.9-55.0.2.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-55.0.2.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-55.0.2.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-55.0.2.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-55.0.2.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-2.6.9-55.0.2.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-devel-2.6.9-55.0.2.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-2.6.9-55.0.2.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-devel-2.6.9-55.0.2.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
