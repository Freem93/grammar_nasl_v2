#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2013-252.
#

include("compat.inc");

if (description)
{
  script_id(71269);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/30 14:48:47 $");

  script_cve_id("CVE-2013-4348", "CVE-2013-4470");
  script_xref(name:"ALAS", value:"2013-252");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2013-252)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Linux kernel before 3.12, when UDP Fragmentation Offload (UFO) is
enabled, does not properly initialize certain data structures, which
allows local users to cause a denial of service (memory corruption and
system crash) or possibly gain privileges via a crafted application
that uses the UDP_CORK option in a setsockopt system call and sends
both short and long packets, related to the ip_ufo_append_data
function in net/ipv4/ip_output.c and the ip6_ufo_append_data function
in net/ipv6/ip6_output.c.

The skb_flow_dissect function in net/core/flow_dissector.c in the
Linux kernel through 3.12 allows remote attackers to cause a denial of
service (infinite loop) via a small value in the IHL field of a packet
with IPIP encapsulation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2013-252.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update kernel' to update your system. You will need to reboot
your system in order for the new kernel to be running."
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/10");
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
if (rpm_check(release:"ALA", reference:"kernel-3.4.71-63.98.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-3.4.71-63.98.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-3.4.71-63.98.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.4.71-63.98.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-3.4.71-63.98.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-3.4.71-63.98.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-3.4.71-63.98.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-3.4.71-63.98.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-3.4.71-63.98.amzn1")) flag++;

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
