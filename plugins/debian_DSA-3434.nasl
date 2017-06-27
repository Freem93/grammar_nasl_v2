#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3434. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(87741);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2015-7513", "CVE-2015-7550", "CVE-2015-8543", "CVE-2015-8550", "CVE-2015-8551", "CVE-2015-8552", "CVE-2015-8569", "CVE-2015-8575", "CVE-2015-8709");
  script_osvdb_id(131683, 131685, 131951, 131952, 132029, 132030, 132031, 132475, 132618);
  script_xref(name:"DSA", value:"3434");

  script_name(english:"Debian DSA-3434-1 : linux - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leak.

  - CVE-2015-7513
    It was discovered that a local user permitted to use the
    x86 KVM subsystem could configure the PIT emulation to
    cause a denial of service (crash).

  - CVE-2015-7550
    Dmitry Vyukov discovered a race condition in the keyring
    subsystem that allows a local user to cause a denial of
    service (crash).

  - CVE-2015-8543
    It was discovered that a local user permitted to create
    raw sockets could cause a denial-of-service by
    specifying an invalid protocol number for the socket.
    The attacker must have the CAP_NET_RAW capability.

  - CVE-2015-8550
    Felix Wilhelm of ERNW discovered that the Xen PV backend
    drivers may read critical data from shared memory
    multiple times. This flaw can be used by a guest kernel
    to cause a denial of service (crash) on the host, or
    possibly for privilege escalation.

  - CVE-2015-8551 / CVE-2015-8552
    Konrad Rzeszutek Wilk of Oracle discovered that the Xen
    PCI backend driver does not adequately validate the
    device state when a guest configures MSIs. This flaw can
    be used by a guest kernel to cause a denial of service
    (crash or disk space exhaustion) on the host.

  - CVE-2015-8569
    Dmitry Vyukov discovered a flaw in the PPTP sockets
    implementation that leads to an information leak to
    local users.

  - CVE-2015-8575
    David Miller discovered a flaw in the Bluetooth SCO
    sockets implementation that leads to an information leak
    to local users.

  - CVE-2015-8709
    Jann Horn discovered a flaw in the permission checks for
    use of the ptrace feature. A local user who has the
    CAP_SYS_PTRACE capability within their own user
    namespace could use this flaw for privilege escalation
    if a more privileged process ever enters that user
    namespace. This affects at least the LXC system.

In addition, this update fixes some regressions in the previous update
:

  - #808293
    A regression in the UDP implementation prevented
    freeradius and some other applications from receiving
    data.

  - #808602 / #808953

    A regression in the USB XHCI driver prevented use of
    some devices in USB 3 SuperSpeed ports.

  - #808973

    A fix to the radeon driver interacted with an existing
    bug to cause a crash at boot when using some AMD/ATI
    graphics cards. This issue only affects wheezy."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=808293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=808602"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=808953"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=808973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8551"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8552"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8569"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8575"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/808293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/808602"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/808953"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/808973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3434"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 3.2.73-2+deb7u2. The oldstable distribution (wheezy)
is not affected by CVE-2015-8709.

For the stable distribution (jessie), these problems have been fixed
in version 3.16.7-ckt20-1+deb8u2. CVE-2015-8543 was already fixed in
version 3.16.7-ckt20-1+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"linux-doc-3.2", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-486", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-4kc-malta", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-5kc-malta", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-686-pae", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-amd64", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-armel", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-armhf", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-i386", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-ia64", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-mips", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-mipsel", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-powerpc", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-s390", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-s390x", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-all-sparc", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-amd64", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-common", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-common-rt", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-iop32x", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-itanium", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-ixp4xx", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-kirkwood", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-loongson-2f", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-mckinley", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-mv78xx0", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-mx5", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-octeon", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-omap", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-orion5x", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-powerpc", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-powerpc-smp", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-powerpc64", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-r4k-ip22", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-r5k-cobalt", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-r5k-ip32", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-rt-686-pae", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-rt-amd64", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-s390x", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-sb1-bcm91250a", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-sb1a-bcm91480b", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-sparc64", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-sparc64-smp", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-versatile", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-headers-3.2.0-4-vexpress", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-486", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-4kc-malta", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-5kc-malta", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-686-pae", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-686-pae-dbg", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-amd64", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-amd64-dbg", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-iop32x", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-itanium", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-ixp4xx", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-kirkwood", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-loongson-2f", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-mckinley", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-mv78xx0", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-mx5", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-octeon", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-omap", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-orion5x", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-powerpc", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-powerpc-smp", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-powerpc64", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-r4k-ip22", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-r5k-cobalt", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-r5k-ip32", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-rt-686-pae", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-rt-686-pae-dbg", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-rt-amd64", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-rt-amd64-dbg", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-s390x", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-s390x-dbg", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-s390x-tape", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-sb1-bcm91250a", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-sb1a-bcm91480b", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-sparc64", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-sparc64-smp", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-versatile", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-image-3.2.0-4-vexpress", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-libc-dev", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-manual-3.2", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-source-3.2", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"linux-support-3.2.0-4", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"xen-linux-system-3.2.0-4-686-pae", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"xen-linux-system-3.2.0-4-amd64", reference:"3.2.73-2+deb7u2")) flag++;
if (deb_check(release:"8.0", prefix:"acpi-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"acpi-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"acpi-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"affs-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"affs-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"affs-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"affs-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"affs-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"affs-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"affs-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"affs-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ata-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"btrfs-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"cdrom-core-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-s390x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"core-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crc-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-s390x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-dm-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-s390x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"crypto-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"dasd-extra-modules-3.16.0-4-s390x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"dasd-modules-3.16.0-4-s390x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"efi-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"efi-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"efi-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"efi-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"event-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-s390x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ext4-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fancontrol-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fancontrol-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-s390x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fat-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fb-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fb-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fb-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fb-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fb-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"firewire-core-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"firewire-core-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"firewire-core-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"firewire-core-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"firewire-core-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"firewire-core-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"firewire-core-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"firewire-core-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"firewire-core-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-s390x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"hfs-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"hfs-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"hfs-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"hfs-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"hfs-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"hfs-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"hfs-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"hfs-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"hyperv-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"hyperv-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"hyperv-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"hypervisor-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"hypervisor-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"i2c-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"i2c-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"i2c-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"i2c-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"i2c-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"input-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ipv6-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"isofs-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jffs2-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"jfs-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-r4k-ip22-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-r5k-ip32-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-s390x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kernel-image-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"leds-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-arm", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-s390", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.8-x86", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-doc-3.16", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-4kc-malta", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-586", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-5kc-malta", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-686-pae", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-amd64", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-arm64", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-armel", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-armhf", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-i386", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-mips", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-mipsel", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-powerpc", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-ppc64el", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-all-s390x", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-amd64", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-arm64", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-armmp", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-armmp-lpae", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-common", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-ixp4xx", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-kirkwood", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-loongson-2e", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-loongson-2f", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-loongson-3", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-octeon", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-orion5x", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-powerpc", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-powerpc-smp", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-powerpc64", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-powerpc64le", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-r4k-ip22", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-r5k-ip32", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-s390x", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-sb1-bcm91250a", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-3.16.0-4-versatile", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-4kc-malta", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-586", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-5kc-malta", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-686-pae", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-686-pae-dbg", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-amd64", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-amd64-dbg", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-arm64", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-arm64-dbg", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-armmp", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-armmp-lpae", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-ixp4xx", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-kirkwood", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-loongson-2e", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-loongson-2f", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-loongson-3", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-octeon", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-orion5x", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-powerpc", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-powerpc-smp", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-powerpc64", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-powerpc64le", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-r4k-ip22", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-r5k-ip32", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-s390x", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-s390x-dbg", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-sb1-bcm91250a", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-3.16.0-4-versatile", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-libc-dev", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-manual-3.16", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-source-3.16", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linux-support-3.16.0-4", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"loop-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-s390x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"md-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"minix-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"minix-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"minix-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"minix-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"minix-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"minix-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"minix-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"minix-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-core-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-core-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-core-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-core-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mmc-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mouse-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mouse-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mouse-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mouse-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mouse-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mouse-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mouse-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mouse-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"mtd-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-s390x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"multipath-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-s390x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nbd-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nfs-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nfs-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nfs-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-s390x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-pcmcia-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-pcmcia-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-pcmcia-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-pcmcia-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-pcmcia-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-shared-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-usb-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"nic-wireless-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pata-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-storage-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-storage-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-storage-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-storage-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pcmcia-storage-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ppp-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"rtc-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"rtc-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sata-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-common-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-s390x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-core-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-extra-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-s390x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scsi-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"serial-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"serial-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"serial-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"serial-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"serial-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"serial-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sound-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sound-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sound-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sound-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sound-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sound-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sound-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sound-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"sound-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"speakup-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"speakup-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"speakup-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"speakup-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"speakup-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"speakup-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"squashfs-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"udf-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uinput-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uinput-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uinput-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uinput-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uinput-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uinput-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uinput-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uinput-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"uinput-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-serial-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-kirkwood-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"usb-storage-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-s390x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtio-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xen-linux-system-3.16.0-4-amd64", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-586-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-686-pae-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-amd64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-powerpc64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-powerpc64le-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-s390x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"xfs-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-4kc-malta-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-arm64-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-armmp-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-loongson-2e-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-loongson-2f-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-loongson-3-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-octeon-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-orion5x-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-powerpc-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-r4k-ip22-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-r5k-ip32-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-sb1-bcm91250a-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zlib-modules-3.16.0-4-versatile-di", reference:"3.16.7-ckt20-1+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
