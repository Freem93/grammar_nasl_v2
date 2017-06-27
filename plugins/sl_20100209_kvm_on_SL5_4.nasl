#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60730);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2010-0297", "CVE-2010-0298", "CVE-2010-0306", "CVE-2010-0309");

  script_name(english:"Scientific Linux Security Update : kvm on SL5.4 i386/x86_64");
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
"The x86 emulator implementation was missing a check for the Current
Privilege Level (CPL) and I/O Privilege Level (IOPL). A user in a
guest could leverage these flaws to cause a denial of service (guest
crash) or possibly escalate their privileges within that guest.
(CVE-2010-0298, CVE-2010-0306)

A flaw was found in the Programmable Interval Timer (PIT) emulation.
Access to the internal data structure pit_state, which represents the
data state of the emulated PIT, was not properly validated in the
pit_ioport_read() function. A privileged guest user could use this
flaw to crash the host. (CVE-2010-0309)

A flaw was found in the USB passthrough handling code. A specially
crafted USB packet sent from inside a guest could be used to trigger a
buffer overflow in the usb_host_handle_control() function, which runs
under the QEMU-KVM context on the host. A user in a guest could
leverage this flaw to cause a denial of service (guest hang or crash)
or possibly escalate their privileges within the host. (CVE-2010-0297)

This update also fixes the following bugs :

  - pvclock MSR values were not preserved during remote
    migration, causing time drift for guests. (BZ#537028)

  - SMBIOS table 4 data is now generated for Windows guests.
    (BZ#545874)

  - if the qemu-kvm '-net user' option was used, unattended
    Windows XP installations did not receive an IP address
    after reboot. (BZ#546562)

  - when being restored from migration, a race condition
    caused Windows Server 2008 R2 guests to hang during
    shutdown. (BZ#546563)

  - the kernel symbol checking on the kvm-kmod build process
    has a safety check for ABI changes. (BZ#547293)

  - on hosts without high-res timers, Windows Server 2003
    guests experienced significant time drift. (BZ#547625)

  - in some situations, installing Windows Server 2008 R2
    from an ISO image resulted in a blue screen
    'BAD_POOL_HEADER' stop error. (BZ#548368)

  - a bug in the grow_refcount_table() error handling caused
    infinite recursion in some cases. This caused the
    qemu-kvm process to hang and eventually crash.
    (BZ#552159)

  - for Windows Server 2003 R2, Service Pack 2, 32-bit
    guests, an 'unhandled vm exit' error could occur during
    reboot on some systems. (BZ#552518)

  - for Windows guests, QEMU could attempt to stop a stopped
    audio device, resulting in a 'snd_playback_stop: ASSERT
    playback_channel->base.active failed' error. (BZ#552519)

  - the Hypercall driver did not reset the device on
    power-down. (BZ#552528)

  - mechanisms have been added to make older savevm versions
    to be emitted in some cases. (BZ#552529)

  - an error in the Makefile prevented users from using the
    source RPM to install KVM. (BZ#552530)

  - guests became unresponsive and could use up to 100% CPU
    when running certain benchmark tests with more than 7
    guests running simultaneously. (BZ#553249)

  - QEMU could terminate randomly with virtio-net and SMP
    enabled. (BZ#561022)

NOTE - The following procedure must be performed before this update
will take effect :

1) Stop all KVM guest virtual machines.

2) Either reboot the hypervisor machine or, as the root user, remove
(using 'modprobe -r [module]') and reload (using 'modprobe [module]')
all of the following modules which are currently running (determined
using 'lsmod'): kvm, ksm, kvm-intel or kvm-amd.

3) Restart the KVM guest virtual machines."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1002&L=scientific-linux-errata&T=0&P=525
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1bc3c4b5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=537028"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=545874"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=546562"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=546563"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=547293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=547625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=548368"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=552159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=552518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=552519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=552528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=552529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=552530"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=553249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=561022"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(16, 119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/09");
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
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kmod-kvm-83-105.el5_4.22")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kvm-83-105.el5_4.22")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kvm-qemu-img-83-105.el5_4.22")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kvm-tools-83-105.el5_4.22")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
