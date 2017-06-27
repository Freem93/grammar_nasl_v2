#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(99218);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/06 13:23:47 $");

  script_cve_id("CVE-2016-10088", "CVE-2016-10142", "CVE-2016-2069", "CVE-2016-2384", "CVE-2016-6480", "CVE-2016-7042", "CVE-2016-7097", "CVE-2016-8399", "CVE-2016-9576");

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

  - It was discovered that a remote attacker could leverage
    the generation of IPv6 atomic fragments to trigger the
    use of fragmentation in an arbitrary IPv6 flow (in
    scenarios in which actual fragmentation of packets is
    not needed) and could subsequently perform any type of a
    fragmentation- based attack against legacy IPv6 nodes
    that do not implement RFC6946. (CVE-2016-10142,
    Moderate)

  - A flaw was discovered in the way the Linux kernel dealt
    with paging structures. When the kernel invalidated a
    paging structure that was not in use locally, it could,
    in principle, race against another CPU that is switching
    to a process that uses the paging structure in question.
    A local user could use a thread running with a stale
    cached virtual->physical translation to potentially
    escalate their privileges if the translation in question
    were writable and the physical page got reused for
    something critical (for example, a page table).
    (CVE-2016-2069, Moderate)

  - A race condition flaw was found in the ioctl_send_fib()
    function in the Linux kernel's aacraid implementation. A
    local attacker could use this flaw to cause a denial of
    service (out-of-bounds access or system crash) by
    changing a certain size value. (CVE-2016-6480, Moderate)

  - It was found that when the gcc stack protector was
    enabled, reading the /proc/keys file could cause a panic
    in the Linux kernel due to stack corruption. This
    happened because an incorrect buffer size was used to
    hold a 64-bit timeout value rendered as weeks.
    (CVE-2016-7042, Moderate)

  - It was found that when file permissions were modified
    via chmod and the user modifying them was not in the
    owning group or capable of CAP_FSETID, the setgid bit
    would be cleared. Setting a POSIX ACL via setxattr sets
    the file permissions as well as the new ACL, but doesn't
    clear the setgid bit in a similar way. This could allow
    a local user to gain group privileges via certain setgid
    applications. (CVE-2016-7097, Moderate)

  - A flaw was found in the Linux networking subsystem where
    a local attacker with CAP_NET_ADMIN capabilities could
    cause an out-of-bounds memory access by creating a
    smaller-than-expected ICMP header and sending to its
    destination via sendto(). (CVE-2016-8399, Moderate)

  - It was found that the blk_rq_map_user_iov() function in
    the Linux kernel's block device implementation did not
    properly restrict the type of iterator, which could
    allow a local attacker to read or write to arbitrary
    kernel memory locations or cause a denial of service
    (use-after-free) by leveraging write access to a /dev/sg
    device. (CVE-2016-9576, CVE-2016-10088, Moderate)

  - A flaw was found in the USB-MIDI Linux kernel driver: a
    double-free error could be triggered for the 'umidi'
    object. An attacker with physical access to the system
    could use this flaw to escalate their privileges.
    (CVE-2016-2384, Low)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1704&L=scientific-linux-errata&F=&S=&P=2945
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3af2bf89"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-696.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-abi-whitelists-2.6.32-696.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-696.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-696.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-696.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-696.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-common-i686-2.6.32-696.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-696.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-696.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-696.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-696.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-696.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-696.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-696.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-696.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-696.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
