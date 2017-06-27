#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61179);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2011-1162", "CVE-2011-1577", "CVE-2011-2494", "CVE-2011-2699", "CVE-2011-2905", "CVE-2011-3188", "CVE-2011-3191", "CVE-2011-3353", "CVE-2011-3359", "CVE-2011-3363", "CVE-2011-3593", "CVE-2011-4326");

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
"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

  - IPv6 fragment identification value generation could
    allow a remote attacker to disrupt a target system's
    networking, preventing legitimate users from accessing
    its services. (CVE-2011-2699, Important)

  - A signedness issue was found in the Linux kernel's CIFS
    (Common Internet File System) implementation. A
    malicious CIFS server could send a specially crafted
    response to a directory read request that would result
    in a denial of service or privilege escalation on a
    system that has a CIFS share mounted. (CVE-2011-3191,
    Important)

  - A flaw was found in the way the Linux kernel handled
    fragmented IPv6 UDP datagrams over the bridge with UDP
    Fragmentation Offload (UFO) functionality on. A remote
    attacker could use this flaw to cause a denial of
    service. (CVE-2011-4326, Important)

  - The way IPv4 and IPv6 protocol sequence numbers and
    fragment IDs were generated could allow a
    man-in-the-middle attacker to inject packets and
    possibly hijack connections. Protocol sequence numbers
    and fragment IDs are now more random. (CVE-2011-3188,
    Moderate)

  - A buffer overflow flaw was found in the Linux kernel's
    FUSE (Filesystem in Userspace) implementation. A local
    user in the fuse group who has access to mount a FUSE
    file system could use this flaw to cause a denial of
    service. (CVE-2011-3353, Moderate)

  - A flaw was found in the b43 driver in the Linux kernel.
    If a system had an active wireless interface that uses
    the b43 driver, an attacker able to send a specially
    crafted frame to that interface could cause a denial of
    service. (CVE-2011-3359, Moderate)

  - A flaw was found in the way CIFS shares with DFS
    referrals at their root were handled. An attacker on the
    local network who is able to deploy a malicious CIFS
    server could create a CIFS network share that, when
    mounted, would cause the client system to crash.
    (CVE-2011-3363, Moderate)

  - A flaw was found in the way the Linux kernel handled
    VLAN 0 frames with the priority tag set. When using
    certain network drivers, an attacker on the local
    network could use this flaw to cause a denial of
    service. (CVE-2011-3593, Moderate)

  - A flaw in the way memory containing security-related
    data was handled in tpm_read() could allow a local,
    unprivileged user to read the results of a previously
    run TPM command. (CVE-2011-1162, Low)

  - A heap overflow flaw was found in the Linux kernel's EFI
    GUID Partition Table (GPT) implementation. A local
    attacker could use this flaw to cause a denial of
    service by mounting a disk that contains specially
    crafted partition tables. (CVE-2011-1577, Low)

  - The I/O statistics from the taskstats subsystem could be
    read without any restrictions. A local, unprivileged
    user could use this flaw to gather confidential
    information, such as the length of a password used in a
    process. (CVE-2011-2494, Low)

  - It was found that the perf tool, a part of the Linux
    kernel's Performance Events implementation, could load
    its configuration file from the current working
    directory. If a local user with access to the perf tool
    were tricked into running perf in a directory that
    contains a specially crafted configuration file, it
    could cause perf to overwrite arbitrary files and
    directories accessible to that user. (CVE-2011-2905,
    Low)

This update also fixes various bugs."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1111&L=scientific-linux-errata&T=0&P=2755
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?905f0b62"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/22");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-131.21.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-131.21.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-131.21.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-131.21.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-131.21.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"i386", reference:"kernel-debuginfo-common-i686-2.6.32-131.21.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-131.21.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-131.21.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-131.21.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-131.21.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-131.21.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-131.21.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-131.21.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
