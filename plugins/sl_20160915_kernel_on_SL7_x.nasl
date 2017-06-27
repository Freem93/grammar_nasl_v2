#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(93557);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2016-3134", "CVE-2016-4997", "CVE-2016-4998");

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
"Security Fix(es) :

  - A security flaw was found in the Linux kernel in the
    mark_source_chains() function in
    'net/ipv4/netfilter/ip_tables.c'. It is possible for a
    user-supplied 'ipt_entry' structure to have a large
    'next_offset' field. This field is not bounds checked
    prior to writing to a counter value at the supplied
    offset. (CVE-2016-3134, Important)

  - A flaw was discovered in processing setsockopt for 32
    bit processes on 64 bit systems. This flaw will allow
    attackers to alter arbitrary kernel memory when
    unloading a kernel module. This action is usually
    restricted to root-privileged users but can also be
    leveraged if the kernel is compiled with CONFIG_USER_NS
    and CONFIG_NET_NS and the user is granted elevated
    privileges. (CVE-2016-4997, Important)

  - An out-of-bounds heap memory access leading to a Denial
    of Service, heap disclosure, or further impact was found
    in setsockopt(). The function call is normally
    restricted to root, however some processes with
    cap_sys_admin may also be able to trigger this flaw in
    privileged container environments. (CVE-2016-4998,
    Moderate)

Bug Fix(es) :

  - In some cases, running the ipmitool command caused a
    kernel panic due to a race condition in the ipmi message
    handler. This update fixes the race condition, and the
    kernel panic no longer occurs in the described scenario.

  - Previously, running I/O-intensive operations in some
    cases caused the system to terminate unexpectedly after
    a NULL pointer dereference in the kernel. With this
    update, a set of patches has been applied to the 3w-9xxx
    and 3w-sas drivers that fix this bug. As a result, the
    system no longer crashes in the described scenario.

  - Previously, the Stream Control Transmission Protocol
    (SCTP) sockets did not inherit the SELinux labels
    properly. As a consequence, the sockets were labeled
    with the unlabeled_t SELinux type which caused SCTP
    connections to fail. The underlying source code has been
    modified, and SCTP connections now works as expected.

  - Previously, the bnx2x driver waited for transmission
    completions when recovering from a parity event, which
    substantially increased the recovery time. With this
    update, bnx2x does not wait for transmission completion
    in the described circumstances. As a result, the
    recovery of bnx2x after a parity event now takes less
    time.

Enhancement(s) :

  - With this update, the audit subsystem enables filtering
    of processes by name besides filtering by PID. Users can
    now audit by executable name (with the '-F
    exe=<path-to-executable>' option), which allows
    expression of many new audit rules. This functionality
    can be used to create events when specific applications
    perform a syscall.

  - With this update, the Nonvolatile Memory Express (NVMe)
    and the multi- queue block layer (blk_mq) have been
    upgraded to the Linux 4.5 upstream version. Previously,
    a race condition between timeout and freeing request in
    blk_mq occurred, which could affect the
    blk_mq_tag_to_rq() function and consequently a kernel
    oops could occur. The provided patch fixes this race
    condition by updating the tags with the active request.
    The patch simplifies blk_mq_tag_to_rq() and ensures that
    the two requests are not active at the same time.

  - The Hyper-V storage driver (storvsc) has been upgraded
    from upstream. This update provides moderate performance
    improvement of I/O operations when using storvscr for
    certain workloads."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1609&L=scientific-linux-errata&F=&S=&P=1852
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eb6e8478"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel 4.6.3 Netfilter Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/16");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-3.10.0-327.36.1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-abi-whitelists-3.10.0-327.36.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-3.10.0-327.36.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-327.36.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-327.36.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-327.36.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-327.36.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-devel-3.10.0-327.36.1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-doc-3.10.0-327.36.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-headers-3.10.0-327.36.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-3.10.0-327.36.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-327.36.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-327.36.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-327.36.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-3.10.0-327.36.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-327.36.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-3.10.0-327.36.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-327.36.1.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
