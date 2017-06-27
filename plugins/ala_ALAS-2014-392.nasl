#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-392.
#

include("compat.inc");

if (description)
{
  script_id(78335);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/11/16 15:47:23 $");

  script_cve_id("CVE-2014-0196", "CVE-2014-1739", "CVE-2014-3153");
  script_xref(name:"ALAS", value:"2014-392");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2014-392)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The media_device_enum_entities function in
drivers/media/media-device.c in the Linux kernel before 3.14.6 does
not initialize a certain data structure, which allows local users to
obtain sensitive information from kernel memory by leveraging
/dev/media0 read access for a MEDIA_IOC_ENUM_ENTITIES ioctl call.

A flaw was found in the way the Linux kernel's futex subsystem handled
the requeuing of certain Priority Inheritance (PI) futexes. A local,
unprivileged user could use this flaw to escalate their privileges on
the system.

The n_tty_write function in drivers/tty/n_tty.c in the Linux kernel
through 3.14.3 does not properly manage tty driver access in the
'LECHO & !OPOST' case, which allows local users to cause a denial of
service (memory corruption and system crash) or gain privileges by
triggering a race condition involving read and write operations with
long strings."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-392.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update kernel' to update your system. You will need to reboot
your system in order for the new kernel to be running."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Android \'Towelroot\' Futex Requeue Kernel Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/21");
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
if (rpm_check(release:"ALA", reference:"kernel-3.10.53-56.140.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-3.10.53-56.140.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-3.10.53-56.140.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.53-56.140.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-3.10.53-56.140.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-3.10.53-56.140.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-3.10.53-56.140.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-3.10.53-56.140.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-3.10.53-56.140.amzn1")) flag++;

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
