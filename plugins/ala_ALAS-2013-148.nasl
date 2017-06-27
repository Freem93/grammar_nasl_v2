#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2013-148.
#

include("compat.inc");

if (description)
{
  script_id(69707);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/30 14:43:53 $");

  script_cve_id("CVE-2012-2100", "CVE-2012-2375", "CVE-2012-4444", "CVE-2012-4565", "CVE-2012-5517");
  script_xref(name:"ALAS", value:"2013-148");
  script_xref(name:"RHSA", value:"2012:1580");

  script_name(english:"Amazon Linux AMI : kernel / nvidia (ALAS-2013-148)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A malicious Network File System version 4 (NFSv4) server could return
a crafted reply to a GETACL request, causing a denial of service on
the client. (CVE-2012-2375 , Moderate)

A divide-by-zero flaw was found in the TCP Illinois congestion control
algorithm implementation in the Linux kernel. If the TCP Illinois
congestion control algorithm were in use (the sysctl
net.ipv4.tcp_congestion_control variable set to 'illinois'), a local,
unprivileged user could trigger this flaw and cause a denial of
service. (CVE-2012-4565 , Moderate)

A NULL pointer dereference flaw was found in the way a new node's hot
added memory was propagated to other nodes' zonelists. By utilizing
this newly added memory from one of the remaining nodes, a local,
unprivileged user could use this flaw to cause a denial of service.
(CVE-2012-5517 , Moderate)

It was found that a prevoius kernel release did not correctly fix the
CVE-2009-4307 issue, a divide-by-zero flaw in the ext4 file system
code. A local, unprivileged user with the ability to mount an ext4
file system could use this flaw to cause a denial of service.
(CVE-2012-2100 , Low)

A flaw was found in the way the Linux kernel's IPv6 implementation
handled overlapping, fragmented IPv6 packets. A remote attacker could
potentially use this flaw to bypass protection mechanisms (such as a
firewall or intrusion detection system (IDS)) when sending network
packets to a target system. (CVE-2012-4444 , Low)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2013-148.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update kernel nvidia' to update your system. You will need to
reboot your system in order for the new kernel to be running."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nvidia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nvidia-kmod-3.2.36-1.46.amzn1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/14");
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
if (rpm_check(release:"ALA", reference:"kernel-3.2.36-1.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-3.2.36-1.46.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-3.2.36-1.46.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.2.36-1.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-3.2.36-1.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-3.2.36-1.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-3.2.36-1.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-3.2.36-1.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-3.2.36-1.46.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"nvidia-310.19-2012.09.10.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"nvidia-kmod-3.2.36-1.46.amzn1-310.19-2012.09.10.amzn1")) flag++;

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
