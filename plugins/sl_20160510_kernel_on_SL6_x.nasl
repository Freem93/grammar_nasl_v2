#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(91643);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/19 14:25:13 $");

  script_cve_id("CVE-2010-5313", "CVE-2013-4312", "CVE-2014-7842", "CVE-2014-8134", "CVE-2015-5156", "CVE-2015-7509", "CVE-2015-8215", "CVE-2015-8324", "CVE-2015-8543");

  script_name(english:"Scientific Linux Security Update : kernel on SL6.x i386/x86_64");
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
"Security Fix(es) :

  - It was found that reporting emulation failures to user
    space could lead to either a local (CVE-2014-7842) or a
    L2->L1 (CVE-2010-5313) denial of service. In the case of
    a local denial of service, an attacker must have access
    to the MMIO area or be able to access an I/O port.
    Please note that on certain systems, HPET is mapped to
    userspace as part of vdso (vvar) and thus an
    unprivileged user may generate MMIO transactions (and
    enter the emulator) this way. (CVE-2010-5313,
    CVE-2014-7842, Moderate)

  - It was found that the Linux kernel did not properly
    account file descriptors passed over the unix socket
    against the process limit. A local user could use this
    flaw to exhaust all available memory on the system.
    (CVE-2013-4312, Moderate)

  - A buffer overflow flaw was found in the way the Linux
    kernel's virtio- net subsystem handled certain fraglists
    when the GRO (Generic Receive Offload) functionality was
    enabled in a bridged network configuration. An attacker
    on the local network could potentially use this flaw to
    crash the system, or, although unlikely, elevate their
    privileges on the system. (CVE-2015-5156, Moderate)

  - It was found that the Linux kernel's IPv6 network stack
    did not properly validate the value of the MTU variable
    when it was set. A remote attacker could potentially use
    this flaw to disrupt a target system's networking
    (packet loss) by setting an invalid MTU value, for
    example, via a NetworkManager daemon that is processing
    router advertisement packets running on the target
    system. (CVE-2015-8215, Moderate)

  - A NULL pointer dereference flaw was found in the way the
    Linux kernel's network subsystem handled socket creation
    with an invalid protocol identifier. A local user could
    use this flaw to crash the system. (CVE-2015-8543,
    Moderate)

  - It was found that the espfix functionality does not work
    for 32-bit KVM paravirtualized guests. A local,
    unprivileged guest user could potentially use this flaw
    to leak kernel stack addresses. (CVE-2014-8134, Low)

  - A flaw was found in the way the Linux kernel's ext4 file
    system driver handled non-journal file systems with an
    orphan list. An attacker with physical access to the
    system could use this flaw to crash the system or,
    although unlikely, escalate their privileges on the
    system. (CVE-2015-7509, Low)

  - A NULL pointer dereference flaw was found in the way the
    Linux kernel's ext4 file system driver handled certain
    corrupted file system images. An attacker with physical
    access to the system could use this flaw to crash the
    system. (CVE-2015-8324, Low)

Notes :

  - Problems have been reported with this kernel and
    VirtualBox. More info is available in the notes for the
    VirtualBox ticket here: <a
    href='https://www.virtualbox.org/ticket/14866'
    target='_blank'>https://www.virtualbox.org/ticket/14866<
    /a>"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1606&L=scientific-linux-errata&F=&S=&P=3658
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?76283b05"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-642.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-abi-whitelists-2.6.32-642.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-642.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-642.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-642.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-642.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-common-i686-2.6.32-642.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-642.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-642.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-642.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-642.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-642.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-642.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-642.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-642.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-642.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
