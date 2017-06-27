#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99106);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/03 13:42:52 $");

  script_cve_id(
    "CVE-2016-10088",
    "CVE-2016-10142",
    "CVE-2016-2069",
    "CVE-2016-2384",
    "CVE-2016-6136",
    "CVE-2016-6480",
    "CVE-2016-6828",
    "CVE-2016-7042",
    "CVE-2016-7097",
    "CVE-2016-8399",
    "CVE-2016-9555",
    "CVE-2016-9576",
    "CVE-2017-6214"
  );
  script_osvdb_id(
    133625,
    134538,
    140971,
    142610,
    142992,
    143514,
    145585,
    147698,
    148195,
    148443,
    150179,
    152453
  );

  script_name(english:"Virtuozzo 6 : parallels-server-bm-release / vzkernel / etc (VZA-2017-025)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the parallels-server-bm-release /
vzkernel / etc packages installed, the Virtuozzo installation on the
remote host is affected by the following vulnerabilities :

  - A flaw was found in the Linux kernel's handling of
    packets with the URG flag. Applications using the
    splice() and tcp_splice_read() functionality can allow
    a remote attacker to force the kernel to enter a
    condition in which it can loop indefinitely.

  - It was discovered that a remote attacker could leverage
    the generation of IPv6 atomic fragments to trigger the
    use of fragmentation in an arbitrary IPv6 flow (in
    scenarios in which actual fragmentation of packets is
    not needed) and could subsequently perform any type of
    a fragmentation-based attack against legacy IPv6 nodes
    that do not implement RFC6946.

  - It was found that the blk_rq_map_user_iov() function in
    the Linux kernel's block device implementation did not
    properly restrict the type of iterator, which could
    allow a local attacker to read or write to arbitrary
    kernel memory locations or cause a denial of service
    (use-after-free) by leveraging write access to a
    /dev/sg device.

  - A flaw was found in the Linux kernel's implementation
    of the SCTP protocol. A remote attacker could trigger
    an out-of-bounds read with an offset of up to 64kB
    potentially causing the system to crash.

  - A flaw was found in the Linux networking subsystem
    where a local attacker with CAP_NET_ADMIN capabilities
    could cause an out-of-bounds memory access by creating
    a smaller-than-expected ICMP header and sending to its
    destination via sendto().

  - It was found that when file permissions were modified
    via chmod and the user modifying them was not in the
    owning group or capable of CAP_FSETID, the setgid bit
    would be cleared. Setting a POSIX ACL via setxattr sets
    the file permissions as well as the new ACL, but
    doesn't clear the setgid bit in a similar way. This
    could allow a local user to gain group privileges via
    certain setgid applications.

  - It was found that when the gcc stack protector was
    enabled, reading the /proc/keys file could cause a
    panic in the Linux kernel due to stack corruption. This
    happened because an incorrect buffer size was used to
    hold a 64-bit timeout value rendered as weeks.

  - A race condition flaw was found in the ioctl_send_fib()
    function in the Linux kernel's aacraid implementation.
    A local attacker could use this flaw to cause a denial
    of service (out-of-bounds access or system crash) by
    changing a certain size value.

  - When creating audit records for parameters to executed
    children processes, an attacker can convince the Linux
    kernel audit subsystem can create corrupt records which
    may allow an attacker to misrepresent or evade logging
    of executing commands.

  - A flaw was discovered in the way the Linux kernel dealt
    with paging structures. When the kernel invalidated a
    paging structure that was not in use locally, it could,
    in principle, race against another CPU that is
    switching to a process that uses the paging structure
    in question. A local user could use a thread running
    with a stale cached virtual->physical translation to
    potentially escalate their privileges if the
    translation in question were writable and the physical
    page got reused for something critical (for example, a
    page table).

  - A flaw was found in the USB-MIDI Linux kernel driver: a
    double-free error could be triggered for the 'umidi'
    object. An attacker with physical access to the system
    could use this flaw to escalate their privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Virtuozzo security advisory.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://help.virtuozzo.com/customer/portal/articles/2777857");
  script_set_attribute(attribute:"see_also", value:"https://rhn.redhat.com/errata/RHSA-2016-2766.html");
  script_set_attribute(attribute:"see_also", value:"https://rhn.redhat.com/errata/RHSA-2017-0036.html");
  script_set_attribute(attribute:"see_also", value:"https://rhn.redhat.com/errata/RHSA-2017-0293.html");
  script_set_attribute(attribute:"see_also", value:"https://rhn.redhat.com/errata/RHSA-2017-0307.html");
  script_set_attribute(attribute:"see_also", value:"https://rhn.redhat.com/errata/RHSA-2017-0817.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected parallels-server-bm-release / vzkernel / etc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-bm-release");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzmodules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzmodules-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Virtuozzo/release", "Host/Virtuozzo/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/Virtuozzo/release");
if (isnull(release) || "Virtuozzo" >!< release) audit(AUDIT_OS_NOT, "Virtuozzo");
os_ver = eregmatch(pattern: "Virtuozzo Linux release ([0-9]+\.[0-9])(\D|$)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 6.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["parallels-server-bm-release-6.0.12-3674",
        "vzkernel-2.6.32-042stab123.1",
        "vzkernel-devel-2.6.32-042stab123.1",
        "vzkernel-firmware-2.6.32-042stab123.1",
        "vzmodules-2.6.32-042stab123.1",
        "vzmodules-devel-2.6.32-042stab123.1"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-6", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "parallels-server-bm-release / vzkernel / etc");
}
