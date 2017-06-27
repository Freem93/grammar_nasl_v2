#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-782.
#

include("compat.inc");

if (description)
{
  script_id(96284);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/02/23 16:41:06 $");

  script_cve_id("CVE-2016-10147", "CVE-2016-8399", "CVE-2016-8650", "CVE-2016-9576", "CVE-2016-9793");
  script_xref(name:"ALAS", value:"2017-782");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2017-782)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in the Linux kernel key management subsystem in which
a local attacker could crash the kernel or corrupt the stack and
additional memory (denial of service) by supplying a specially crafted
RSA key. This flaw panics the machine during the verification of the
RSA key. (CVE-2016-8650)

The blk_rq_map_user_iov function in block/blk-map.c in the Linux
kernel before 4.8.14 does not properly restrict the type of iterator,
which allows local users to read or write to arbitrary kernel memory
locations or cause a denial of service (use-after-free) by leveraging
access to a /dev/sg device. (CVE-2016-9576)

The sock_setsockopt function in net/core/sock.c in the Linux kernel
before 4.8.14 mishandles negative values of sk_sndbuf and sk_rcvbuf,
which allows local users to cause a denial of service (memory
corruption and system crash) or possibly have unspecified other impact
by leveraging the CAP_NET_ADMIN capability for a crafted setsockopt
system call with the (1) SO_SNDBUFFORCE or (2) SO_RCVBUFFORCE option.
(CVE-2016-9793)

A flaw was found in the Linux networking subsystem where a local
attacker with CAP_NET_ADMIN capabilities could cause an out of bounds
read by creating a smaller-than-expected ICMP header and sending to
its destination via sendto(). (CVE-2016-8399)

Algorithms not compatible with mcryptd could be spawned by mcryptd
with a direct crypto_alloc_tfm invocation using a 'mcryptd(alg)' name
construct. This causes mcryptd to crash the kernel if an arbitrary
'alg' is incompatible and not intended to be used with mcryptd.
(CVE-2016-10147)

(Updated on 2017-01-19: CVE-2016-8399 was fixed in this release but
was previously not part of this errata.)

(Updated on 2017-02-22: CVE-2016-10147 was fixed in this release but
was previously not part of this errata.)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-782.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update kernel' to update your system. You will need to reboot
your system in order for the new kernel to be running."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"kernel-4.4.39-34.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-4.4.39-34.54.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-4.4.39-34.54.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.4.39-34.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-4.4.39-34.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-4.4.39-34.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-4.4.39-34.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-4.4.39-34.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-4.4.39-34.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-devel-4.4.39-34.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-4.4.39-34.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-4.4.39-34.54.amzn1")) flag++;

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
