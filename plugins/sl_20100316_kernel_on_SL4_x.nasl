#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60748);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2009-4271", "CVE-2009-4538", "CVE-2010-0003", "CVE-2010-0007", "CVE-2010-0008", "CVE-2010-0307");

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
"This update fixes the following security issues :

  - a NULL pointer dereference flaw was found in the
    sctp_rcv_ootb() function in the Linux kernel Stream
    Control Transmission Protocol (SCTP) implementation. A
    remote attacker could send a specially crafted SCTP
    packet to a target system, resulting in a denial of
    service. (CVE-2010-0008, Important)

  - a NULL pointer dereference flaw was found in the Linux
    kernel. During a core dump, the kernel did not check if
    the Virtual Dynamically-linked Shared Object page was
    accessible. On Intel 64 and AMD64 systems, a local,
    unprivileged user could use this flaw to cause a kernel
    panic by running a crafted 32-bit application.
    (CVE-2009-4271, Important)

  - an information leak was found in the
    print_fatal_signal() implementation in the Linux kernel.
    When '/proc/sys/kernel/print-fatal-signals' is set to 1
    (the default value is 0), memory that is reachable by
    the kernel could be leaked to user-space. This issue
    could also result in a system crash. Note that this flaw
    only affected the i386 architecture. (CVE-2010-0003,
    Moderate)

  - on AMD64 systems, it was discovered that the kernel did
    not ensure the ELF interpreter was available before
    making a call to the SET_PERSONALITY macro. A local
    attacker could use this flaw to cause a denial of
    service by running a 32-bit application that attempts to
    execute a 64-bit application. (CVE-2010-0307, Moderate)

  - missing capability checks were found in the ebtables
    implementation, used for creating an Ethernet bridge
    firewall. This could allow a local, unprivileged user to
    bypass intended capability restrictions and modify
    ebtables rules. (CVE-2010-0007, Low)

This update also fixes the following bugs :

  - under some circumstances, a locking bug could have
    caused an online ext3 file system resize to deadlock,
    which may have, in turn, caused the file system or the
    entire system to become unresponsive. In either case, a
    reboot was required after the deadlock. With this
    update, using resize2fs to perform an online resize of
    an ext3 file system works as expected. (BZ#553135)

  - some ATA and SCSI devices were not honoring the
    barrier=1 mount option, which could result in data loss
    after a crash or power loss. This update applies a patch
    to the Linux SCSI driver to ensure ordered write
    caching. This solution does not provide cache flushes;
    however, it does provide data integrity on devices that
    have no write caching (or where write caching is
    disabled) and no command queuing. For systems that have
    command queuing or write cache enabled there is no
    guarantee of data integrity after a crash. (BZ#560563)

  - it was found that lpfc_find_target() could loop
    continuously when scanning a list of nodes due to a
    missing spinlock. This missing spinlock allowed the list
    to be changed after the list_empty() test, resulting in
    a NULL value, causing the loop. This update adds the
    spinlock, resolving the issue. (BZ#561453)

  - the fix for CVE-2009-4538 provided by RHSA-2010:0020
    introduced a regression, preventing Wake on LAN (WoL)
    working for network devices using the Intel PRO/1000
    Linux driver, e1000e. Attempting to configure WoL for
    such devices resulted in the following error, even when
    configuring valid options :

    'Cannot set new wake-on-lan settings: Operation not
    supported not setting wol'

This update resolves this regression, and WoL now works as expected
for network devices using the e1000e driver. (BZ#565496)

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1003&L=scientific-linux-errata&T=0&P=1650
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a25594c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=553135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=560563"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=561453"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=565496"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/16");
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
if (rpm_check(release:"SL4", reference:"kernel-2.6.9-89.0.23.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-devel-2.6.9-89.0.23.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-doc-2.6.9-89.0.23.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-89.0.23.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-89.0.23.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-89.0.23.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-89.0.23.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-2.6.9-89.0.23.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-devel-2.6.9-89.0.23.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-2.6.9-89.0.23.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-devel-2.6.9-89.0.23.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
