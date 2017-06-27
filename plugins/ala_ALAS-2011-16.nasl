#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2011-16.
#

include("compat.inc");

if (description)
{
  script_id(69575);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/30 14:43:52 $");

  script_cve_id("CVE-2011-1833", "CVE-2011-2723", "CVE-2011-2918", "CVE-2011-3188", "CVE-2011-3191");
  script_xref(name:"ALAS", value:"2011-16");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2011-16)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The skb_gro_header_slow function in include/linux/netdevice.h in the
Linux kernel before 2.6.39.4, when Generic Receive Offload (GRO) is
enabled, resets certain fields in incorrect situations, which allows
remote attackers to cause a denial of service (system crash) via
crafted network traffic.

Race condition in the ecryptfs_mount function in fs/ecryptfs/main.c in
the eCryptfs subsystem in the Linux kernel before 3.1 allows local
users to bypass intended file permissions via a mount.ecryptfs_private
mount with a mismatched uid.

The (1) IPv4 and (2) IPv6 implementations in the Linux kernel before
3.1 use a modified MD4 algorithm to generate sequence numbers and
Fragment Identification values, which makes it easier for remote
attackers to cause a denial of service (disrupted networking) or
hijack network sessions by predicting these values and sending crafted
packets.

Integer signedness error in the CIFSFindNext function in
fs/cifs/cifssmb.c in the Linux kernel before 3.1 allows remote CIFS
servers to cause a denial of service (memory corruption) or possibly
have unspecified other impact via a large length value in a response
to a read request for a directory.

The Performance Events subsystem in the Linux kernel before 3.1 does
not properly handle event overflows associated with
PERF_COUNT_SW_CPU_CLOCK events, which allows local users to cause a
denial of service (system hang) via a crafted application."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2011-16.html"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/31");
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
if (rpm_check(release:"ALA", reference:"kernel-2.6.35.14-97.44.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-2.6.35.14-97.44.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.35.14-97.44.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.35.14-97.44.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-2.6.35.14-97.44.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-2.6.35.14-97.44.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-2.6.35.14-97.44.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-2.6.35.14-97.44.amzn1")) flag++;

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
