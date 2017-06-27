#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-289.
#

include("compat.inc");

if (description)
{
  script_id(72745);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/30 14:48:48 $");

  script_cve_id("CVE-2013-7263", "CVE-2013-7265", "CVE-2014-0069", "CVE-2014-1874");
  script_xref(name:"ALAS", value:"2014-289");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2014-289)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The pn_recvmsg function in net/phonet/datagram.c in the Linux kernel
before 3.12.4 updates a certain length value before ensuring that an
associated data structure has been initialized, which allows local
users to obtain sensitive information from kernel stack memory via a
(1) recvfrom, (2) recvmmsg, or (3) recvmsg system call.

The security_context_to_sid_core function in
security/selinux/ss/services.c in the Linux kernel before 3.13.4
allows local users to cause a denial of service (system crash) by
leveraging the CAP_MAC_ADMIN capability to set a zero-length security
context.

The Linux kernel before 3.12.4 updates certain length values before
ensuring that associated data structures have been initialized, which
allows local users to obtain sensitive information from kernel stack
memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system call,
related to net/ipv4/ping.c, net/ipv4/raw.c, net/ipv4/udp.c,
net/ipv6/raw.c, and net/ipv6/udp.c.

The cifs_iovec_write function in fs/cifs/file.c in the Linux kernel
through 3.13.5 does not properly handle uncached write operations that
copy fewer than the requested number of bytes, which allows local
users to obtain sensitive information from kernel memory, cause a
denial of service (memory corruption and system crash), or possibly
gain privileges via a writev system call with a crafted pointer."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-289.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update kernel' to update your system. You will need to reboot
your system in order for the new kernel to be running."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"kernel-3.4.82-69.112.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-3.4.82-69.112.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-3.4.82-69.112.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.4.82-69.112.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-3.4.82-69.112.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-3.4.82-69.112.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-3.4.82-69.112.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-3.4.82-69.112.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-3.4.82-69.112.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-debuginfo-common-i686 / etc");
}
