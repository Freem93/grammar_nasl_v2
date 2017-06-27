#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-328.
#

include("compat.inc");

if (description)
{
  script_id(78271);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/30 14:55:42 $");

  script_cve_id("CVE-2014-0055", "CVE-2014-0077", "CVE-2014-2309", "CVE-2014-2523");
  script_xref(name:"ALAS", value:"2014-328");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2014-328)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The ip6_route_add function in net/ipv6/route.c in the Linux kernel
through 3.13.6 does not properly count the addition of routes, which
allows remote attackers to cause a denial of service (memory
consumption) via a flood of ICMPv6 Router Advertisement packets.

drivers/vhost/net.c in the Linux kernel before 3.13.10, when mergeable
buffers are disabled, does not properly validate packet lengths, which
allows guest OS users to cause a denial of service (memory corruption
and host OS crash) or possibly gain privileges on the host OS via
crafted packets, related to the handle_rx and get_rx_bufs functions.

net/netfilter/nf_conntrack_proto_dccp.c in the Linux kernel through
3.13.6 uses a DCCP header pointer incorrectly, which allows remote
attackers to cause a denial of service (system crash) or possibly
execute arbitrary code via a DCCP packet that triggers a call to the
(1) dccp_new, (2) dccp_packet, or (3) dccp_error function.

The get_rx_bufs function in drivers/vhost/net.c in the vhost-net
subsystem in the Linux kernel package before 2.6.32-431.11.2 on Red
Hat Enterprise Linux (RHEL) 6 does not properly handle
vhost_get_vq_desc errors, which allows guest OS users to cause a
denial of service (host OS crash) via unspecified vectors."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-328.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update kernel' to update your system. You will need to reboot
your system in order for the new kernel to be running."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/12");
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
if (rpm_check(release:"ALA", reference:"kernel-3.10.37-47.135.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-3.10.37-47.135.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-3.10.37-47.135.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.37-47.135.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-3.10.37-47.135.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-3.10.37-47.135.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-3.10.37-47.135.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-3.10.37-47.135.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-3.10.37-47.135.amzn1")) flag++;

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
