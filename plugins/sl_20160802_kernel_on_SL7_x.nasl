#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(92719);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2015-8660", "CVE-2016-2143", "CVE-2016-4470");

  script_name(english:"Scientific Linux Security Update : kernel on SL7.x x86_64");
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
"To see the complete list of bug fixes, users are directed to the
related Knowledge Article :

Security Fix(es) :

  - A flaw was found in the Linux kernel's keyring handling
    code, where in key_reject_and_link() an uninitialised
    variable would eventually lead to arbitrary free address
    which could allow attacker to use a use-after-free style
    attack. (CVE-2016-4470, Important)

  - The ovl_setattr function in fs/overlayfs/inode.c in the
    Linux kernel through 4.3.3 attempts to merge distinct
    setattr operations, which allows local users to bypass
    intended access restrictions and modify the attributes
    of arbitrary overlay files via a crafted application.
    (CVE-2015-8660, Moderate)

  - It was reported that on s390x, the fork of a process
    with four page table levels will cause memory corruption
    with a variety of symptoms. All processes are created
    with three level page table and a limit of 4TB for the
    address space. If the parent process has four page table
    levels with a limit of 8PB, the function that duplicates
    the address space will try to copy memory areas outside
    of the address space limit for the child process.
    (CVE-2016-2143, Moderate)

Bug Fix(es) :

  - The glibc headers and the Linux headers share certain
    definitions of key structures that are required to be
    defined in kernel and in userspace. In some instances
    both userspace and sanitized kernel headers have to be
    included in order to get the structure definitions
    required by the user program. Unfortunately because the
    glibc and Linux headers don't coordinate this can result
    in compilation errors. The glibc headers have therefore
    been fixed to coordinate with Linux UAPI-based headers.
    With the header coordination compilation errors no
    longer occur.

  - When running the TCP/IPv6 traffic over the mlx4_en
    networking interface on the big endian architectures,
    call traces reporting about a 'hw csum failure' could
    occur. With this update, the mlx4_en driver has been
    fixed by correction of the checksum calculation for the
    big endian architectures. As a result, the call trace
    error no longer appears in the log messages.

  - Under significant load, some applications such as
    logshifter could generate bursts of log messages too
    large for the system logger to spool. Due to a race
    condition, log messages from that application could then
    be lost even after the log volume dropped to manageable
    levels. This update fixes the kernel mechanism used to
    notify the transmitter end of the socket used by the
    system logger that more space is available on the
    receiver side, removing a race condition which
    previously caused the sender to stop transmitting new
    messages and allowing all log messages to be processed
    correctly.

  - Previously, after heavy open or close of the Accelerator
    Function Unit (AFU) contexts, the interrupt packet went
    out and the AFU context did not see any interrupts.
    Consequently, a kernel panic could occur. The provided
    patch set fixes handling of the interrupt requests, and
    kernel panic no longer occurs in the described
    situation.

  - net: recvfrom would fail on short buffer.

  - Backport rhashtable changes from upstream.

  - Server Crashing after starting Glusterd &amp; creating
    volumes.

  - RAID5 reshape deadlock fix.

  - BDX perf uncore support fix."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1608&L=scientific-linux-errata&F=&S=&P=3509
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?194750af"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Overlayfs Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/04");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-abi-whitelists-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-devel-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-doc-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-headers-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-3.10.0-327.28.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-327.28.2.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
