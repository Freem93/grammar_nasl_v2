#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3791. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(97357);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/03/09 14:56:42 $");

  script_cve_id("CVE-2016-6786", "CVE-2016-6787", "CVE-2016-8405", "CVE-2016-9191", "CVE-2017-2583", "CVE-2017-2584", "CVE-2017-2596", "CVE-2017-2618", "CVE-2017-5549", "CVE-2017-5551", "CVE-2017-5897", "CVE-2017-5970", "CVE-2017-6001", "CVE-2017-6074");
  script_osvdb_id(146761, 148187, 148246, 148247, 150064, 150690, 150782, 150899, 151239, 151568, 151927, 152205, 152302);
  script_xref(name:"DSA", value:"3791");

  script_name(english:"Debian DSA-3791-1 : linux - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or have other
impacts.

  - CVE-2016-6786 / CVE-2016-6787
    It was discovered that the performance events subsystem
    does not properly manage locks during certain
    migrations, allowing a local attacker to escalate
    privileges. This can be mitigated by disabling
    unprivileged use of performance events:sysctl
    kernel.perf_event_paranoid=3

  - CVE-2016-8405
    Peter Pi of Trend Micro discovered that the frame buffer
    video subsystem does not properly check bounds while
    copying color maps to userspace, causing a heap buffer
    out-of-bounds read, leading to information disclosure.

  - CVE-2016-9191
    CAI Qian discovered that reference counting is not
    properly handled within proc_sys_readdir in the sysctl
    implementation, allowing a local denial of service
    (system hang) or possibly privilege escalation.

  - CVE-2017-2583
    Xiaohan Zhang reported that KVM for amd64 does not
    correctly emulate loading of a null stack selector. This
    can be used by a user in a guest VM for denial of
    service (on an Intel CPU) or to escalate privileges
    within the VM (on an AMD CPU).

  - CVE-2017-2584
    Dmitry Vyukov reported that KVM for x86 does not
    correctly emulate memory access by the SGDT and SIDT
    instructions, which can result in a use-after-free and
    information leak.

  - CVE-2017-2596
    Dmitry Vyukov reported that KVM leaks page references
    when emulating a VMON for a nested hypervisor. This can
    be used by a privileged user in a guest VM for denial of
    service or possibly to gain privileges in the host.

  - CVE-2017-2618
    It was discovered that an off-by-one in the handling of
    SELinux attributes in /proc/pid/attr could result in
    local denial of service.

  - CVE-2017-5549
    It was discovered that the KLSI KL5KUSB105 serial USB
    device driver could log the contents of uninitialised
    kernel memory, resulting in an information leak.

  - CVE-2017-5551
    Jan Kara found that changing the POSIX ACL of a file on
    tmpfs never cleared its set-group-ID flag, which should
    be done if the user changing it is not a member of the
    group-owner. In some cases, this would allow the
    user-owner of an executable to gain the privileges of
    the group-owner.

  - CVE-2017-5897
    Andrey Konovalov discovered an out-of-bounds read flaw
    in the ip6gre_err function in the IPv6 networking code.

  - CVE-2017-5970
    Andrey Konovalov discovered a denial-of-service flaw in
    the IPv4 networking code. This can be triggered by a
    local or remote attacker if a local UDP or raw socket
    has the IP_RETOPTS option enabled.

  - CVE-2017-6001
    Di Shen discovered a race condition between concurrent
    calls to the performance events subsystem, allowing a
    local attacker to escalate privileges. This flaw exists
    because of an incomplete fix of CVE-2016-6786. This can
    be mitigated by disabling unprivileged use of
    performance events: sysctl kernel.perf_event_paranoid=3

  - CVE-2017-6074
    Andrey Konovalov discovered a use-after-free
    vulnerability in the DCCP networking code, which could
    result in denial of service or local privilege
    escalation. On systems that do not already have the dccp
    module loaded, this can be mitigated by disabling
    it:echo >> /etc/modprobe.d/disable-dccp.conf install
    dccp false"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-6786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-6787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-8405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-9191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-2583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-2584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-2596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-2618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5551"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-6001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-6786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-6074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2017/dsa-3791"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux packages.

For the stable distribution (jessie), these problems have been fixed
in version 3.16.39-1+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"8.0", prefix:"acpi-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"acpi-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"acpi-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"affs-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"affs-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"affs-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"affs-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"affs-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"affs-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"affs-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"affs-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"dasd-extra-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"dasd-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"efi-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"efi-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"efi-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"efi-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fancontrol-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fancontrol-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fb-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fb-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fb-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fb-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fb-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firewire-core-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firewire-core-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firewire-core-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firewire-core-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firewire-core-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firewire-core-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firewire-core-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firewire-core-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firewire-core-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"hfs-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"hfs-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"hfs-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"hfs-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"hfs-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"hfs-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"hfs-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"hfs-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"hyperv-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"hyperv-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"hyperv-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"hypervisor-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"hypervisor-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"i2c-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"i2c-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"i2c-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"i2c-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"i2c-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ipv6-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"jffs2-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"leds-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-arm", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-s390", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-x86", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-doc-3.16", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-4kc-malta", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-586", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-5kc-malta", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-686-pae", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-amd64", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-arm64", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-armel", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-armhf", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-i386", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-mips", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-mipsel", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-powerpc", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-ppc64el", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-s390x", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-amd64", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-arm64", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-armmp", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-armmp-lpae", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-common", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-ixp4xx", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-kirkwood", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-loongson-2e", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-loongson-2f", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-loongson-3", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-octeon", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-orion5x", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-powerpc", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-powerpc-smp", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-powerpc64", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-powerpc64le", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-r4k-ip22", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-r5k-ip32", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-s390x", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-sb1-bcm91250a", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-versatile", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-4kc-malta", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-586", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-5kc-malta", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-686-pae", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-686-pae-dbg", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-amd64", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-amd64-dbg", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-arm64", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-arm64-dbg", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-armmp", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-armmp-lpae", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-ixp4xx", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-kirkwood", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-loongson-2e", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-loongson-2f", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-loongson-3", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-octeon", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-orion5x", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-powerpc", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-powerpc-smp", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-powerpc64", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-powerpc64le", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-r4k-ip22", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-r5k-ip32", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-s390x", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-s390x-dbg", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-sb1-bcm91250a", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-versatile", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-libc-dev", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-manual-3.16", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-source-3.16", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-support-3.16.0-4", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"minix-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"minix-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"minix-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"minix-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"minix-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"minix-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"minix-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"minix-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-core-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-core-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-core-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-core-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mouse-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mouse-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mouse-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mouse-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mouse-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mouse-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mouse-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mouse-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mtd-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nfs-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nfs-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nfs-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-pcmcia-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-pcmcia-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-pcmcia-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-pcmcia-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-pcmcia-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-storage-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-storage-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-storage-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-storage-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-storage-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"rtc-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"rtc-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"serial-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"serial-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"serial-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"serial-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"serial-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"serial-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sound-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sound-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sound-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sound-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sound-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sound-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sound-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sound-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sound-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"speakup-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"speakup-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"speakup-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"speakup-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"speakup-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"speakup-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"uinput-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"uinput-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"uinput-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"uinput-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"uinput-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"uinput-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"uinput-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"uinput-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"uinput-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xen-linux-system-3.16.0-4-amd64", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
