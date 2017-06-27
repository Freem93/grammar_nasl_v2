#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-603.
#

include("compat.inc");

if (description)
{
  script_id(86634);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/10/28 21:03:36 $");

  script_cve_id("CVE-2015-2925", "CVE-2015-7613", "CVE-2015-8787");
  script_xref(name:"ALAS", value:"2015-603");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2015-603)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A race condition in the IPC object implementation in the Linux kernel
through 4.2.3 allows local users to gain privileges by triggering an
ipc_addid call that leads to uid and gid comparisons against
uninitialized data, related to msg.c, shm.c, and util.c.
(CVE-2015-7613)

Linux kernels built with the name spaces support(CONFIG_NAMESPACE) is
vulnerable to a potential privilege escalation flaw. It could occur
when a process within a container escapes the intended bind mounts to
access the full file system. A privileged user inside a container
could use this flaw to potentially gain full privileges on a system.
(CVE-2015-2925)

A NULL pointer dereference vulnerability was found in the Linux
kernel's TCP stack, in net/netfilter/nf_nat_redirect.c in the
nf_nat_redirect_ipv4() function. A remote, unauthenticated user could
exploit this flaw to create a system crash (denial of service).
(CVE-2015-8787)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-603.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum clean all' followed by 'yum update kernel' to update your
system. You will need to reboot your system in order for the new
kernel to be running."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"kernel-4.1.10-17.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-4.1.10-17.31.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-4.1.10-17.31.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.1.10-17.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-4.1.10-17.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-4.1.10-17.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-4.1.10-17.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-4.1.10-17.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-4.1.10-17.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-devel-4.1.10-17.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-4.1.10-17.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-4.1.10-17.31.amzn1")) flag++;

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
