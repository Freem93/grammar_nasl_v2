#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-772.
#

include("compat.inc");

if (description)
{
  script_id(95609);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/01/23 15:31:52 $");

  script_cve_id("CVE-2016-8645", "CVE-2016-8655", "CVE-2016-9083", "CVE-2016-9084");
  script_xref(name:"ALAS", value:"2016-772");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2016-772)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2016-8645 kernel: a BUG() statement can be hit in
net/ipv4/tcp_input.c

It was discovered that the Linux kernel since 3.6-rc1 with
net.ipv4.tcp_fastopen; set to 1 can hit BUG() statement in
tcp_collapse() function after making a number of certain syscalls
leading to a possible system crash.

CVE-2016-8655 kernel: Race condition in packet_set_ring leads to use
after free

A race condition issue leading to a use-after-free flaw was found in
the way the raw packet sockets implementation in the Linux kernel
networking subsystem handled synchronization while creating the
TPACKET_V3 ring buffer. A local user able to open a raw packet socket
(requires the CAP_NET_RAW capability) could use this flaw to elevate
their privileges on the system.

CVE-2016-9083 kernel: State machine confusion bug in vfio driver
leading to memory corruption

A flaw was discovered in the Linux kernel's implementation of VFIO. An
attacker issuing an ioctl can create a situation where memory is
corrupted and modify memory outside of the expected area. This may
overwrite kernel memory and subvert kernel execution.

CVE-2016-9084 kernel: Integer overflow when using kzalloc in vfio
driver

The use of a kzalloc with an integer multiplication allowed an integer
overflow condition to be reached in vfio_pci_intrs.c. This combined
with CVE-2016-9083 may allow an attacker to craft an attack and use
unallocated memory, potentially crashing the machine."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-772.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update kernel' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"kernel-4.4.35-33.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-4.4.35-33.55.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-4.4.35-33.55.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.4.35-33.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-4.4.35-33.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-4.4.35-33.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-4.4.35-33.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-4.4.35-33.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-4.4.35-33.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-devel-4.4.35-33.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-4.4.35-33.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-4.4.35-33.55.amzn1")) flag++;

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
