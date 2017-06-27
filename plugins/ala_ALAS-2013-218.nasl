#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2013-218.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(70222);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/30 14:43:54 $");

  script_cve_id("CVE-2012-6548", "CVE-2013-0914", "CVE-2013-1059", "CVE-2013-1848", "CVE-2013-2128", "CVE-2013-2232", "CVE-2013-2234", "CVE-2013-2634", "CVE-2013-2635", "CVE-2013-2852", "CVE-2013-3222", "CVE-2013-3224", "CVE-2013-3225", "CVE-2013-3301");
  script_xref(name:"ALAS", value:"2013-218");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2013-218)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The bt_sock_recvmsg function in net/bluetooth/af_bluetooth.c in the
Linux kernel before 3.9-rc7 does not properly initialize a certain
length variable, which allows local users to obtain sensitive
information from kernel stack memory via a crafted recvmsg or recvfrom
system call.

The udf_encode_fh function in fs/udf/namei.c in the Linux kernel
before 3.6 does not initialize a certain structure member, which
allows local users to obtain sensitive information from kernel heap
memory via a crafted application.

The ftrace implementation in the Linux kernel before 3.8.8
allows local users to cause a denial of service (NULL
pointer dereference and system crash) or possibly have
unspecified other impact by leveraging the CAP_SYS_ADMIN
capability for write access to the (1) set_ftrace_pid or (2)
set_graph_function file, and then making an lseek system
call.

The rtnl_fill_ifinfo function in net/core/rtnetlink.c in the
Linux kernel before 3.8.4 does not initialize a certain
structure member, which allows local users to obtain
sensitive information from kernel stack memory via a crafted
application.

The ip6_sk_dst_check function in net/ipv6/ip6_output.c in the Linux
kernel before 3.10 allows local users to cause a denial of service
(system crash) by using an AF_INET6 socket for a connection to an IPv4
interface.

The tcp_read_sock function in net/ipv4/tcp.c in the Linux kernel
before 2.6.34 does not properly manage skb consumption, which allows
local users to cause a denial of service (system crash) via a crafted
splice system call for a TCP socket.

The rfcomm_sock_recvmsg function in net/bluetooth/rfcomm/sock.c in the
Linux kernel before 3.9-rc7 does not initialize a certain length
variable, which allows local users to obtain sensitive information
from kernel stack memory via a crafted recvmsg or recvfrom system
call.

Format string vulnerability in the b43_request_firmware function in
drivers/net/wireless/b43/main.c in the Broadcom B43 wireless driver in
the Linux kernel through 3.9.4 allows local users to gain privileges
by leveraging root access and including format string specifiers in an
fwpostfix modprobe parameter, leading to improper construction of an
error message.

The (1) key_notify_sa_flush and (2) key_notify_policy_flush functions
in net/key/af_key.c in the Linux kernel before 3.10 do not initialize
certain structure members, which allows local users to obtain
sensitive information from kernel heap memory by reading a broadcast
message from the notify interface of an IPSec key_socket.

The vcc_recvmsg function in net/atm/common.c in the Linux kernel
before 3.9-rc7 does not initialize a certain length variable, which
allows local users to obtain sensitive information from kernel stack
memory via a crafted recvmsg or recvfrom system call.

The flush_signal_handlers function in kernel/signal.c in the Linux
kernel before 3.8.4 preserves the value of the sa_restorer field
across an exec operation, which makes it easier for local users to
bypass the ASLR protection mechanism via a crafted application
containing a sigaction system call.

net/dcb/dcbnl.c in the Linux kernel before 3.8.4 does not initialize
certain structures, which allows local users to obtain sensitive
information from kernel stack memory via a crafted application.

fs/ext3/super.c in the Linux kernel before 3.8.4 uses incorrect
arguments to functions in certain circumstances related to printk
input, which allows local users to conduct format-string attacks and
possibly gain privileges via a crafted application.

net/ceph/auth_none.c in the Linux kernel through 3.10 allows remote
attackers to cause a denial of service (NULL pointer dereference and
system crash) or possibly have unspecified other impact via an
auth_reply message that triggers an attempted build_request operation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2013-218.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update kernel' to update your system. You will need to reboot
your system in order for the new kernel to be running."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/01");
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
if (rpm_check(release:"ALA", reference:"kernel-3.4.57-48.42.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-3.4.57-48.42.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-3.4.57-48.42.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.4.57-48.42.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-3.4.57-48.42.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-3.4.57-48.42.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-3.4.57-48.42.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-3.4.57-48.42.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-3.4.57-48.42.amzn1")) flag++;

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
