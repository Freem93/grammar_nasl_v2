#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3804. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(97615);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/09 14:56:42 $");

  script_cve_id("CVE-2016-9588", "CVE-2017-2636", "CVE-2017-5669", "CVE-2017-5986", "CVE-2017-6214", "CVE-2017-6345", "CVE-2017-6346", "CVE-2017-6348", "CVE-2017-6353");
  script_xref(name:"DSA", value:"3804");

  script_name(english:"Debian DSA-3804-1 : linux - security update");
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

  - CVE-2016-9588
    Jim Mattson discovered that the KVM implementation for
    Intel x86 processors does not properly handle #BP and
    #OF exceptions in an L2 (nested) virtual machine. A
    local attacker in an L2 guest VM can take advantage of
    this flaw to cause a denial of service for the L1 guest
    VM.

  - CVE-2017-2636
    Alexander Popov discovered a race condition flaw in the
    n_hdlc line discipline that can lead to a double free. A
    local unprivileged user can take advantage of this flaw
    for privilege escalation. On systems that do not already
    have the n_hdlc module loaded, this can be mitigated by
    disabling it:echo >> /etc/modprobe.d/disable-n_hdlc.conf
    install n_hdlc false

  - CVE-2017-5669
    Gareth Evans reported that privileged users can map
    memory at address 0 through the shmat() system call.
    This could make it easier to exploit other kernel
    security vulnerabilities via a set-UID program.

  - CVE-2017-5986
    Alexander Popov reported a race condition in the SCTP
    implementation that can be used by local users to cause
    a denial-of-service (crash). The initial fix for this
    was incorrect and introduced further security issues (
    CVE-2017-6353 ). This update includes a later fix that
    avoids those. On systems that do not already have the
    sctp module loaded, this can be mitigated by disabling
    it:echo >> /etc/modprobe.d/disable-sctp.conf install
    sctp false

  - CVE-2017-6214
    Dmitry Vyukov reported a bug in the TCP implementation's
    handling of urgent data in the splice() system call.
    This can be used by a remote attacker for
    denial-of-service (hang) against applications that read
    from TCP sockets with splice().

  - CVE-2017-6345
    Andrey Konovalov reported that the LLC type 2
    implementation incorrectly assigns socket buffer
    ownership. This can be used by a local user to cause a
    denial-of-service (crash). On systems that do not
    already have the llc2 module loaded, this can be
    mitigated by disabling it:echo >>
    /etc/modprobe.d/disable-llc2.conf install llc2 false

  - CVE-2017-6346
    Dmitry Vyukov reported a race condition in the raw
    packet (af_packet) fanout feature. Local users with the
    CAP_NET_RAW capability (in any user namespace) can use
    this for denial-of-service and possibly for privilege
    escalation.

  - CVE-2017-6348
    Dmitry Vyukov reported that the general queue
    implementation in the IrDA subsystem does not properly
    manage multiple locks, possibly allowing local users to
    cause a denial-of-service (deadlock) via crafted
    operations on IrDA devices."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-9588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-2636"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-6353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-6214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-6345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-6346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-6348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2017/dsa-3804"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux packages.

For the stable distribution (jessie), these problems have been fixed
in version 3.16.39-1+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/09");
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
if (deb_check(release:"8.0", prefix:"acpi-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"acpi-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"acpi-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"affs-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"affs-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"affs-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"affs-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"affs-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"affs-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"affs-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"affs-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"dasd-extra-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"dasd-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"efi-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"efi-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"efi-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"efi-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fancontrol-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fancontrol-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fb-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fb-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fb-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fb-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fb-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"firewire-core-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"firewire-core-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"firewire-core-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"firewire-core-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"firewire-core-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"firewire-core-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"firewire-core-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"firewire-core-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"firewire-core-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"hfs-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"hfs-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"hfs-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"hfs-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"hfs-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"hfs-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"hfs-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"hfs-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"hyperv-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"hyperv-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"hyperv-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"hypervisor-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"hypervisor-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"i2c-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"i2c-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"i2c-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"i2c-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"i2c-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ipv6-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jffs2-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"leds-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-arm", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-s390", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-x86", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-doc-3.16", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-4kc-malta", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-586", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-5kc-malta", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-686-pae", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-amd64", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-arm64", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-armel", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-armhf", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-i386", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-mips", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-mipsel", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-powerpc", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-ppc64el", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-s390x", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-amd64", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-arm64", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-armmp", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-armmp-lpae", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-common", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-ixp4xx", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-kirkwood", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-loongson-2e", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-loongson-2f", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-loongson-3", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-octeon", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-orion5x", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-powerpc", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-powerpc-smp", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-powerpc64", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-powerpc64le", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-r4k-ip22", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-r5k-ip32", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-s390x", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-sb1-bcm91250a", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-versatile", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-4kc-malta", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-586", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-5kc-malta", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-686-pae", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-686-pae-dbg", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-amd64", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-amd64-dbg", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-arm64", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-arm64-dbg", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-armmp", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-armmp-lpae", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-ixp4xx", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-kirkwood", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-loongson-2e", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-loongson-2f", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-loongson-3", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-octeon", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-orion5x", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-powerpc", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-powerpc-smp", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-powerpc64", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-powerpc64le", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-r4k-ip22", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-r5k-ip32", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-s390x", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-s390x-dbg", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-sb1-bcm91250a", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-versatile", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-libc-dev", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-manual-3.16", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-source-3.16", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-support-3.16.0-4", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"minix-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"minix-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"minix-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"minix-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"minix-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"minix-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"minix-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"minix-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-core-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-core-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-core-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-core-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mouse-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mouse-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mouse-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mouse-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mouse-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mouse-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mouse-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mouse-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mtd-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nfs-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nfs-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nfs-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-pcmcia-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-pcmcia-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-pcmcia-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-pcmcia-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-pcmcia-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-storage-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-storage-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-storage-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-storage-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-storage-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"rtc-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"rtc-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"serial-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"serial-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"serial-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"serial-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"serial-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"serial-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sound-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sound-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sound-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sound-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sound-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sound-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sound-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sound-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sound-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"speakup-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"speakup-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"speakup-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"speakup-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"speakup-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"speakup-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uinput-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uinput-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uinput-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uinput-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uinput-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uinput-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uinput-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uinput-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uinput-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-kirkwood-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xen-linux-system-3.16.0-4-amd64", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-586-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-686-pae-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-amd64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-powerpc64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-powerpc64le-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-s390x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-4kc-malta-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-arm64-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-armmp-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-loongson-2e-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-loongson-2f-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-loongson-3-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-octeon-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-orion5x-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-powerpc-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.39-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-versatile-di", reference:"3.16.39-1+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
