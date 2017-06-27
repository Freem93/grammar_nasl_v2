#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2153. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(51818);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/26 15:53:37 $");

  script_cve_id("CVE-2010-0435", "CVE-2010-3699", "CVE-2010-4158", "CVE-2010-4162", "CVE-2010-4163", "CVE-2010-4242", "CVE-2010-4243", "CVE-2010-4248", "CVE-2010-4249", "CVE-2010-4258", "CVE-2010-4342", "CVE-2010-4346", "CVE-2010-4526", "CVE-2010-4527", "CVE-2010-4529", "CVE-2010-4565", "CVE-2010-4649", "CVE-2010-4656", "CVE-2010-4668", "CVE-2011-0521");
  script_bugtraq_id(42582, 44661, 44758, 44793, 45004, 45014, 45028, 45037, 45039, 45159, 45321, 45323, 45556, 45629, 45660, 45661, 45986);
  script_xref(name:"DSA", value:"2153");

  script_name(english:"Debian DSA-2153-1 : linux-2.6 - privilege escalation/denial of service/information leak");
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
leak. The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2010-0435
    Gleb Napatov reported an issue in the KVM subsystem that
    allows virtual machines to cause a denial of service of
    the host machine by executing mov to/from DR
    instructions.

  - CVE-2010-3699
    Keir Fraser provided a fix for an issue in the Xen
    subsystem. A guest can cause a denial of service on the
    host by retaining a leaked reference to a device. This
    can result in a zombie domain, xenwatch process hangs,
    and xm command failures.

  - CVE-2010-4158
    Dan Rosenberg discovered an issue in the socket filters
    subsystem, allowing local unprivileged users to obtain
    the contents of sensitive kernel memory.

  - CVE-2010-4162
    Dan Rosenberg discovered an overflow issue in the block
    I/O subsystem that allows local users to map large
    numbers of pages, resulting in a denial of service due
    to invocation of the out of memory killer.

  - CVE-2010-4163
    Dan Rosenberg discovered an issue in the block I/O
    subsystem. Due to improper validation of iov segments,
    local users can trigger a kernel panic resulting in a
    denial of service.

  - CVE-2010-4242
    Alan Cox reported an issue in the Bluetooth subsystem.
    Local users with sufficient permission to access HCI
    UART devices can cause a denial of service (NULL pointer
    dereference) due to a missing check for an existing tty
    write operation.

  - CVE-2010-4243
    Brad Spengler reported a denial-of-service issue in the
    kernel memory accounting system. By passing large
    argv/envp values to exec, local users can cause the out
    of memory killer to kill processes owned by other users.

  - CVE-2010-4248
    Oleg Nesterov reported an issue in the POSIX CPU timers
    subsystem. Local users can cause a denial of service
    (Oops) due to incorrect assumptions about thread group
    leader behavior.

  - CVE-2010-4249
    Vegard Nossum reported an issue with the UNIX socket
    garbage collector. Local users can consume all of LOWMEM
    and decrease system performance by overloading the
    system with inflight sockets.

  - CVE-2010-4258
    Nelson Elhage reported an issue in Linux oops handling.
    Local users may be able to obtain elevated privileges if
    they are able to trigger an oops with a process' fs set
    to KERNEL_DS.

  - CVE-2010-4342
    Nelson Elhage reported an issue in the Econet protocol.
    Remote attackers can cause a denial of service by
    sending an Acorn Universal Networking packet over UDP.

  - CVE-2010-4346
    Tavis Ormandy discovered an issue in the
    install_special_mapping routine which allows local users
    to bypass the mmap_min_addr security restriction.
    Combined with an otherwise low severity local denial of
    service vulnerability (NULL pointer dereference), a
    local user could obtain elevated privileges.

  - CVE-2010-4526
    Eugene Teo reported a race condition in the Linux SCTP
    implementation. Remote users can cause a denial of
    service (kernel memory corruption) by transmitting an
    ICMP unreachable message to a locked socket.

  - CVE-2010-4527
    Dan Rosenberg reported two issues in the OSS soundcard
    driver. Local users with access to the device (members
    of group 'audio' on default Debian installations) may
    access to sensitive kernel memory or cause a buffer
    overflow, potentially leading to an escalation of
    privileges.

  - CVE-2010-4529
    Dan Rosenberg reported an issue in the Linux kernel IrDA
    socket implementation on non-x86 architectures. Local
    users may be able to gain access to sensitive kernel
    memory via a specially crafted IRLMP_ENUMDEVICES
    getsockopt call.

  - CVE-2010-4565
    Dan Rosenberg reported an issue in the Linux CAN
    protocol implementation. Local users can obtain the
    address of a kernel heap object which might help
    facilitate system exploitation.

  - CVE-2010-4649
    Dan Carpenter reported an issue in the uverb handling of
    the InfiniBand subsystem. A potential buffer overflow
    may allow local users to cause a denial of service
    (memory corruption) by passing in a large cmd.ne value.

  - CVE-2010-4656
    Kees Cook reported an issue in the driver for
    I/O-Warrior USB devices. Local users with access to
    these devices may be able to overrun kernel buffers,
    resulting in a denial of service or privilege
    escalation.

  - CVE-2010-4668
    Dan Rosenberg reported an issue in the block subsystem.
    A local user can cause a denial of service (kernel
    panic) by submitting certain 0-length I/O requests.

  - CVE-2011-0521
    Dan Carpenter reported an issue in the DVB driver for
    AV7110 cards. Local users can pass a negative info->num
    value, corrupting kernel memory and causing a denial of
    service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4243"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4342"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4526"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4649"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0521"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2153"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux-2.6 and user-mode-linux packages.

For the stable distribution (lenny), this problem has been fixed in
version 2.6.26-26lenny2.

The following matrix lists additional source packages that were
rebuilt for compatibility with or to take advantage of this update :

                         Debian 5.0 (lenny)     
  user-mode-linux        2.6.26-1um-2+26lenny2  
Note that these updates will not become active until after your system
is rebooted."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"linux-base", reference:"2.6.26-26lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
