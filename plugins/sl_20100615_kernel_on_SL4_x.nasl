#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60802);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2009-3726", "CVE-2010-1173", "CVE-2010-1437");

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
"Security fixes :

  - a NULL pointer dereference flaw was found in the Linux
    kernel NFSv4 implementation. Several of the NFSv4 file
    locking functions failed to check whether a file had
    been opened on the server before performing locking
    operations on it. A local, unprivileged user on a system
    with an NFSv4 share mounted could possibly use this flaw
    to cause a kernel panic (denial of service) or escalate
    their privileges. (CVE-2009-3726, Important)

  - a flaw was found in the sctp_process_unk_param()
    function in the Linux kernel Stream Control Transmission
    Protocol (SCTP) implementation. A remote attacker could
    send a specially crafted SCTP packet to an SCTP
    listening port on a target system, causing a kernel
    panic (denial of service). (CVE-2010-1173, Important)

  - a race condition between finding a keyring by name and
    destroying a freed keyring was found in the Linux kernel
    key management facility. A local, unprivileged user
    could use this flaw to cause a kernel panic (denial of
    service) or escalate their privileges. (CVE-2010-1437,
    Important)

Red Hat would like to thank Simon Vallet for responsibly reporting
CVE-2009-3726; and Jukka Taimisto and Olli Jarva of Codenomicon Ltd,
Nokia Siemens Networks, and Wind River on behalf of their customer,
for responsibly reporting CVE-2010-1173.

Bug fixes :

  - RHBA-2007:0791 introduced a regression in the Journaling
    Block Device (JBD). Under certain circumstances,
    removing a large file (such as 300 MB or more) did not
    result in inactive memory being freed, leading to the
    system having a large amount of inactive memory. Now,
    the memory is correctly freed. (BZ#589155)

  - the timer_interrupt() routine did not scale lost real
    ticks to logical ticks correctly, possibly causing time
    drift for 64-bit Scientific Linux 4 KVM (Kernel-based
    Virtual Machine) guests that were booted with the
    'divider=x' kernel parameter set to a value greater than
    1. 'warning: many lost ticks' messages may have been
    logged on the affected guest systems. (BZ#590551)

  - a bug could have prevented NFSv3 clients from having the
    most up-to-date file attributes for files on a given
    NFSv3 file system. In cases where a file type changed,
    such as if a file was removed and replaced with a
    directory of the same name, the NFSv3 client may not
    have noticed this change until stat(2) was called (for
    example, by running 'ls -l'). (BZ#596372)

  - RHBA-2007:0791 introduced bugs in the Linux kernel PCI-X
    subsystem. These could have caused a system deadlock on
    some systems where the BIOS set the default Maximum
    Memory Read Byte Count (MMRBC) to 4096, and that also
    use the Intel PRO/1000 Linux driver, e1000. Errors such
    as 'e1000: eth[x]: e1000_clean_tx_irq: Detected Tx Unit
    Hang' were logged. (BZ#596374)

  - an out of memory condition in a KVM guest, using the
    virtio-net network driver and also under heavy network
    stress, could have resulted in that guest being unable
    to receive network traffic. Users had to manually remove
    and re-add the virtio_net module and restart the network
    service before networking worked as expected. Such
    memory conditions no longer prevent KVM guests receiving
    network traffic. (BZ#597310)

  - when an SFQ qdisc that limited the queue size to two
    packets was added to a network interface, sending
    traffic through that interface resulted in a kernel
    crash. Such a qdisc no longer results in a kernel crash.
    (BZ#597312)

  - when an NFS client opened a file with the O_TRUNC flag
    set, it received a valid stateid, but did not use that
    stateid to perform the SETATTR call. Such cases were
    rejected by Red Hat Enterprise Linux 4 NFS servers with
    an 'NFS4ERR_BAD_STATEID' error, possibly preventing some
    NFS clients from writing files to an NFS file system.
    (BZ#597314)

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1006&L=scientific-linux-errata&T=0&P=1387
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d349837d"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=589155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=590551"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=596372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=596374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=597310"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=597312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=597314"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/15");
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
if (rpm_check(release:"SL4", reference:"kernel-2.6.9-89.0.26.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-devel-2.6.9-89.0.26.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-doc-2.6.9-89.0.26.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-89.0.26.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-89.0.26.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-89.0.26.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-89.0.26.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-2.6.9-89.0.26.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-devel-2.6.9-89.0.26.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-2.6.9-89.0.26.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-devel-2.6.9-89.0.26.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
