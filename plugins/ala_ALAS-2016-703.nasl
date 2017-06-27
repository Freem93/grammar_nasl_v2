#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-703.
#

include("compat.inc");

if (description)
{
  script_id(91241);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/11/14 14:25:18 $");

  script_cve_id("CVE-2015-8839", "CVE-2016-0758", "CVE-2016-3961", "CVE-2016-4485", "CVE-2016-4486", "CVE-2016-4557", "CVE-2016-4558", "CVE-2016-4565", "CVE-2016-4581");
  script_xref(name:"ALAS", value:"2016-703");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2016-703)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Linux kernel did not properly suppress hugetlbfs support in x86 PV
guests, which could allow local PV guest users to cause a denial of
service (guest OS crash) by attempting to access a hugetlbfs mapped
area. (CVE-2016-3961 / XSA-174)

A flaw was found in the way the Linux kernel's ASN.1 DER decoder
processed certain certificate files with tags of indefinite length. A
local, unprivileged user could use a specially crafted X.509
certificate DER file to crash the system or, potentially, escalate
their privileges on the system. (CVE-2016-0758)

Multiple race conditions in the ext4 filesystem implementation in the
Linux kernel before 4.5 allow local users to cause a denial of service
(disk corruption) by writing to a page that is associated with a
different user's file after unsynchronized hole punching and
page-fault handling. (CVE-2015-8839)

The following flaws were also fixed in this version :

CVE-2016-4557 : Use after free vulnerability via double fdput

CVE-2016-4581 : Slave being first propagated copy causes oops in
propagate_mnt

CVE-2016-4486 : Information leak in rtnetlink

CVE-2016-4485 : Information leak in llc module

CVE-2016-4558 : bpf: refcnt overflow

CVE-2016-4565 : infiniband: Unprivileged process can overwrite kernel
memory using rdma_ucm.ko

CVE-2016-0758 : tags with indefinite length can corrupt pointers in
asn1_find_indefinite_length()

CVE-2015-8839 : ext4 filesystem page fault race condition with
fallocate call."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-703.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update kernel' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux BPF Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"kernel-4.4.10-22.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-4.4.10-22.54.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-4.4.10-22.54.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.4.10-22.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-4.4.10-22.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-4.4.10-22.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-4.4.10-22.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-4.4.10-22.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-4.4.10-22.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-devel-4.4.10-22.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-4.4.10-22.54.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-4.4.10-22.54.amzn1")) flag++;

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
