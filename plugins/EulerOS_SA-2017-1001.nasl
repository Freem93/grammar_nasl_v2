#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99848);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/04 13:21:27 $");

  script_cve_id(
    "CVE-2016-10088",
    "CVE-2016-3672",
    "CVE-2016-8666",
    "CVE-2016-9555",
    "CVE-2016-9576",
    "CVE-2016-9588",
    "CVE-2016-9806"
  );
  script_osvdb_id(
    136761,
    145649,
    145694,
    147698,
    148137,
    148443,
    148861
  );

  script_name(english:"EulerOS 2.0 SP1 : kernel (EulerOS-SA-2017-1001)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - arch/x86/kvm/vmx.c in the Linux kernel through 4.9
    mismanages the #BP and #OF exceptions, which allows
    guest OS users to cause a denial of service (guest OS
    crash) by declining to handle an exception thrown by an
    L2 guest.(CVE-2016-9588)

  - The IP stack in the Linux kernel before 4.6 allows
    remote attackers to cause a denial of service (stack
    consumption and panic) or possibly have unspecified
    other impact by triggering use of the GRO path for
    packets with tunnel stacking, as demonstrated by
    interleaved IPv4 headers and GRE headers, a related
    issue to CVE-2016-7039.(CVE-2016-8666)

  - The blk_rq_map_user_iov function in block/blk-map.c in
    the Linux kernel before 4.8.14 does not properly
    restrict the type of iterator, which allows local users
    to read or write to arbitrary kernel memory locations
    or cause a denial of service (use-after-free) by
    leveraging access to a /dev/sg device.(CVE-2016-9576)

  - Race condition in the netlink_dump function in
    net/netlink/af_netlink.c in the Linux kernel before
    4.6.3 allows local users to cause a denial of service
    (double free) or possibly have unspecified other impact
    via a crafted application that makes sendmsg system
    calls, leading to a free operation associated with a
    new dump that started earlier than
    anticipated.(CVE-2016-9806)

  - The sg implementation in the Linux kernel through 4.9
    does not properly restrict write operations in
    situations where the KERNEL_DS option is set, which
    allows local users to read or write to arbitrary kernel
    memory locations or cause a denial of service
    (use-after-free) by leveraging access to a /dev/sg
    device, related to block/bsg.c and drivers/scsi/sg.c.
    NOTE: this vulnerability exists because of an
    incomplete fix for CVE-2016-9576.(CVE-2016-10088)

  - A flaw was found in the Linux kernel's implementation
    of the SCTP protocol. A remote attacker could trigger
    an out-of-bounds read with an offset of up to 64kB
    potentially causing the system to crash.
    (CVE-2016-9555)

  - The arch_pick_mmap_layout function in
    arch/x86/mm/mmap.c in the Linux kernel through 4.5.2
    does not properly randomize the legacy base address,
    which makes it easier for local users to defeat the
    intended restrictions on the ADDR_NO_RANDOMIZE flag,
    and bypass the ASLR protection mechanism for a setuid
    or setgid program, by disabling stack-consumption
    resource limits.(CVE-2016-3672)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1001
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5780220");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(1)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1");

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-229.46.1.111",
        "kernel-debug-3.10.0-229.46.1.111",
        "kernel-debuginfo-3.10.0-229.46.1.111",
        "kernel-debuginfo-common-x86_64-3.10.0-229.46.1.111",
        "kernel-devel-3.10.0-229.46.1.111",
        "kernel-headers-3.10.0-229.46.1.111",
        "kernel-tools-3.10.0-229.46.1.111",
        "kernel-tools-libs-3.10.0-229.46.1.111",
        "perf-3.10.0-229.46.1.111",
        "python-perf-3.10.0-229.46.1.111"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
