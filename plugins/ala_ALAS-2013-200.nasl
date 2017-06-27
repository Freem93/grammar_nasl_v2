#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2013-200.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(69758);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/30 14:43:54 $");

  script_cve_id("CVE-2012-6544", "CVE-2012-6545", "CVE-2013-0914", "CVE-2013-1767", "CVE-2013-1773", "CVE-2013-1929", "CVE-2013-3222", "CVE-2013-3224", "CVE-2013-3231", "CVE-2013-3235");
  script_xref(name:"ALAS", value:"2013-200");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2013-200)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Heap-based buffer overflow in the tg3_read_vpd function in
drivers/net/ethernet/broadcom/tg3.c in the Linux kernel before 3.8.6
allows physically proximate attackers to cause a denial of service
(system crash) or possibly execute arbitrary code via crafted firmware
that specifies a long string in the Vital Product Data (VPD) data
structure.

Use-after-free vulnerability in the shmem_remount_fs function in
mm/shmem.c in the Linux kernel before 3.7.10 allows local users to
gain privileges or cause a denial of service (system crash) by
remounting a tmpfs filesystem without specifying a required mpol (aka
mempolicy) mount option.

The vcc_recvmsg function in net/atm/common.c in the Linux kernel
before 3.9-rc7 does not initialize a certain length variable, which
allows local users to obtain sensitive information from kernel stack
memory via a crafted recvmsg or recvfrom system call.

The flush_signal_handlers function in kernel/signal.c in the Linux
kernel before 3.8.4 preserves the value of the sa_restorer field
across an exec operation, which makes it easier for local users to
bypass the ASLR protection mechanism via a crafted application
containing a sigaction system call.

The llc_ui_recvmsg function in net/llc/af_llc.c in the Linux kernel
before 3.9-rc7 does not initialize a certain length variable, which
allows local users to obtain sensitive information from kernel stack
memory via a crafted recvmsg or recvfrom system call.

net/tipc/socket.c in the Linux kernel before 3.9-rc7 does not
initialize a certain data structure and a certain length variable,
which allows local users to obtain sensitive information from kernel
stack memory via a crafted recvmsg or recvfrom system call.

Buffer overflow in the VFAT filesystem implementation in the Linux
kernel before 3.3 allows local users to gain privileges or cause a
denial of service (system crash) via a VFAT write operation on a
filesystem with the utf8 mount option, which is not properly handled
during UTF-8 to UTF-16 conversion.

The Bluetooth RFCOMM implementation in the Linux kernel before 3.6
does not properly initialize certain structures, which allows local
users to obtain sensitive information from kernel memory via a crafted
application.

The Bluetooth protocol stack in the Linux kernel before 3.6 does not
properly initialize certain structures, which allows local users to
obtain sensitive information from kernel stack memory via a crafted
application that targets the (1) L2CAP or (2) HCI implementation.

The bt_sock_recvmsg function in net/bluetooth/af_bluetooth.c in the
Linux kernel before 3.9-rc7 does not properly initialize a certain
length variable, which allows local users to obtain sensitive
information from kernel stack memory via a crafted recvmsg or recvfrom
system call."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2013-200.html"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/11");
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
if (rpm_check(release:"ALA", reference:"kernel-3.4.48-45.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-3.4.48-45.46.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-3.4.48-45.46.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.4.48-45.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-3.4.48-45.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-3.4.48-45.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-3.4.48-45.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-3.4.48-45.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-3.4.48-45.46.amzn1")) flag++;

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
