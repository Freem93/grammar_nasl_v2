#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2011-26.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(69585);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/30 14:43:52 $");

  script_cve_id("CVE-2011-1162", "CVE-2011-1577", "CVE-2011-2494", "CVE-2011-2699", "CVE-2011-2905", "CVE-2011-3188", "CVE-2011-3191", "CVE-2011-3353", "CVE-2011-3359", "CVE-2011-3363", "CVE-2011-3593", "CVE-2011-4110", "CVE-2011-4132", "CVE-2011-4326");
  script_xref(name:"ALAS", value:"2011-26");
  script_xref(name:"RHSA", value:"2011:1465");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2011-26)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IPv6 fragment identification value generation could allow a remote
attacker to disrupt a target system's networking, preventing
legitimate users from accessing its services. (CVE-2011-2699 ,
Important)

A signedness issue was found in the Linux kernel's CIFS (Common
Internet File System) implementation. A malicious CIFS server could
send a specially crafted response to a directory read request that
would result in a denial of service or privilege escalation on a
system that has a CIFS share mounted. (CVE-2011-3191 , Important)

A flaw was found in the way the Linux kernel handled fragmented IPv6
UDP datagrams over the bridge with UDP Fragmentation Offload (UFO)
functionality on. A remote attacker could use this flaw to cause a
denial of service. (CVE-2011-4326 , Important)

The way IPv4 and IPv6 protocol sequence numbers and fragment IDs were
generated could allow a man-in-the-middle attacker to inject packets
and possibly hijack connections. Protocol sequence numbers and
fragment IDs are now more random. (CVE-2011-3188 , Moderate)

A buffer overflow flaw was found in the Linux kernel's FUSE
(Filesystem in Userspace) implementation. A local user in the fuse
group who has access to mount a FUSE file system could use this flaw
to cause a denial of service. (CVE-2011-3353 , Moderate)

A flaw was found in the b43 driver in the Linux kernel. If a system
had an active wireless interface that uses the b43 driver, an attacker
able to send a specially crafted frame to that interface could cause a
denial of service. (CVE-2011-3359 , Moderate)

A flaw was found in the way CIFS shares with DFS referrals at their
root were handled. An attacker on the local network who is able to
deploy a malicious CIFS server could create a CIFS network share that,
when mounted, would cause the client system to crash. (CVE-2011-3363 ,
Moderate)

A flaw was found in the way the Linux kernel handled VLAN 0 frames
with the priority tag set. When using certain network drivers, an
attacker on the local network could use this flaw to cause a denial of
service. (CVE-2011-3593 , Moderate)

A flaw in the way memory containing security-related data was handled
in tpm_read() could allow a local, unprivileged user to read the
results of a previously run TPM command. (CVE-2011-1162 , Low)

A heap overflow flaw was found in the Linux kernel's EFI GUID
Partition Table (GPT) implementation. A local attacker could use this
flaw to cause a denial of service by mounting a disk that contains
specially crafted partition tables. (CVE-2011-1577 , Low)

The I/O statistics from the taskstats subsystem could be read without
any restrictions. A local, unprivileged user could use this flaw to
gather confidential information, such as the length of a password used
in a process. (CVE-2011-2494 , Low)

It was found that the perf tool, a part of the Linux kernel's
Performance Events implementation, could load its configuration file
from the current working directory. If a local user with access to the
perf tool were tricked into running perf in a directory that contains
a specially crafted configuration file, it could cause perf to
overwrite arbitrary files and directories accessible to that user.
(CVE-2011-2905 , Low)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2011-26.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update kernel' to update your system. You will need to reboot
your system in order for the new kernel to be running."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/AmazonLinux/release")) audit(AUDIT_OS_NOT, "Amazon Linux AMI");
if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"kernel-2.6.35.14-106.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-2.6.35.14-106.49.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.35.14-106.49.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.35.14-106.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-2.6.35.14-106.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-2.6.35.14-106.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-2.6.35.14-106.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-2.6.35.14-106.49.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-debuginfo-common-i686 / etc");
}
