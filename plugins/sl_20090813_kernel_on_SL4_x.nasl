#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60641);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_cve_id("CVE-2009-1389", "CVE-2009-1439", "CVE-2009-1633");

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
"CVE-2009-1439 kernel: cifs: memory overwrite when saving
nativeFileSystem field during mount

CVE-2009-1633 kernel: cifs: fix potential buffer overruns when
converting unicode strings sent by server

CVE-2009-1389 kernel: r8169: fix crash when large packets are received

These updated packages fix the following security issues :

  - Michael Tokarev reported a flaw in the Realtek r8169
    Ethernet driver in the Linux kernel. This driver allowed
    interfaces using this driver to receive frames larger
    than what could be handled. This could lead to a remote
    denial of service or code execution. (CVE-2009-1389,
    Important)

  - a buffer overflow flaw was found in the CIFSTCon()
    function of the Linux kernel Common Internet File System
    (CIFS) implementation. When mounting a CIFS share, a
    malicious server could send an overly-long string to the
    client, possibly leading to a denial of service or
    privilege escalation on the client mounting the CIFS
    share. (CVE-2009-1439, Important)

  - several flaws were found in the way the Linux kernel
    CIFS implementation handles Unicode strings. CIFS
    clients convert Unicode strings sent by a server to
    their local character sets, and then write those strings
    into memory. If a malicious server sent a long enough
    string, it could write past the end of the target memory
    region and corrupt other memory areas, possibly leading
    to a denial of service or privilege escalation on the
    client mounting the CIFS share. (CVE-2009-1633,
    Important)

These updated packages also fix the following bugs :

  - when using network bonding in the 'balance-tlb' or
    'balance-alb' mode, the primary setting for the primary
    slave device was lost when said device was brought down
    (ifdown). Bringing the slave interface back up (ifup)
    did not restore the primary setting (the device was not
    made the active slave). (BZ#507563)

  - a bug in timer_interrupt() may have caused the system
    time to move up to two days or more into the future, or
    to be delayed for several minutes.This bug only affected
    Intel 64 and AMD64 systems that have the High Precision
    Event Timer (HPET) enabled in the BIOS, and could have
    caused problems for applications that require timing to
    be accurate. (BZ#508835)

  - a race condition was resolved in the Linux kernel block
    layer between show_partition() and rescan_partitions().
    This could have caused a NULL pointer dereference in
    show_partition(), leading to a system crash (kernel
    panic). This issue was most likely to occur on systems
    running monitoring software that regularly scanned hard
    disk partitions, or from repeatedly running commands
    that probe for partition information. (BZ#512310)

  - previously, the Stratus memory tracker missed certain
    modified pages. With this update, information about the
    type of page (small page or huge page) is passed to the
    Stratus memory tracker, which resolves this issue. The
    fix for this issue does not affect systems that do not
    use memory tracking. (BZ#513182)

  - a bug may have caused a system crash when using the
    cciss driver, due toan uninitialized kernel structure. A
    reported case of this issue occurred after issuing
    consecutive SCSI TUR commands (sg_turs sends SCSI
    test-unit-ready commands in a loop). (BZ#513189)

  - a bug in the SCSI implementation caused 'Aborted Command
    - internal target failure' errors to be sent to
    Device-Mapper Multipath, without retries, resulting in
    Device-Mapper Multipath marking the path as failed and
    making a path group switch. With this update, all errors
    that return a sense key in the SCSI mid layer (including
    'Aborted Command - internal target failure') are
    retried. (BZ#514007)

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0908&L=scientific-linux-errata&T=0&P=1472
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa2d1d88"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=507563"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=508835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=512310"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=513182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=513189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=514007"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"kernel-2.6.9-89.0.7.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-devel-2.6.9-89.0.7.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-doc-2.6.9-89.0.7.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-89.0.7.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-89.0.7.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-89.0.7.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-89.0.7.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-2.6.9-89.0.7.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-devel-2.6.9-89.0.7.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-2.6.9-89.0.7.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-devel-2.6.9-89.0.7.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
