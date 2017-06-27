#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2310. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(56285);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2009-4067", "CVE-2011-0712", "CVE-2011-1020", "CVE-2011-2209", "CVE-2011-2211", "CVE-2011-2213", "CVE-2011-2484", "CVE-2011-2491", "CVE-2011-2492", "CVE-2011-2495", "CVE-2011-2496", "CVE-2011-2497", "CVE-2011-2525", "CVE-2011-2928", "CVE-2011-3188", "CVE-2011-3191");
  script_bugtraq_id(46419, 46567, 47321, 48254, 48333, 48383, 48441, 48472, 48641, 48687, 49141, 49256, 49289, 49295, 49408);
  script_xref(name:"DSA", value:"2310");

  script_name(english:"Debian DSA-2310-1 : linux-2.6 - privilege escalation/denial of service/information leak");
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

  - CVE-2009-4067
    Rafael Dominguez Vega of MWR InfoSecurity reported an
    issue in the auerswald module, a driver for Auerswald
    PBX/System Telephone USB devices. Attackers with
    physical access to a system's USB ports could obtain
    elevated privileges using a specially crafted USB
    device.

  - CVE-2011-0712
    Rafael Dominguez Vega of MWR InfoSecurity reported an
    issue in the caiaq module, a USB driver for Native
    Instruments USB audio devices. Attackers with physical
    access to a system's USB ports could obtain elevated
    privileges using a specially crafted USB device.

  - CVE-2011-1020
    Kees Cook discovered an issue in the /proc filesystem
    that allows local users to gain access to sensitive
    process information after execution of a setuid binary.

  - CVE-2011-2209
    Dan Rosenberg discovered an issue in the osf_sysinfo()
    system call on the alpha architecture. Local users could
    obtain access to sensitive kernel memory.

  - CVE-2011-2211
    Dan Rosenberg discovered an issue in the osf_wait4()
    system call on the alpha architecture permitting local
    users to gain elevated privileges.

  - CVE-2011-2213
    Dan Rosenberg discovered an issue in the INET socket
    monitoring interface. Local users could cause a denial
    of service by injecting code and causing the kernel to
    execute an infinite loop.

  - CVE-2011-2484
    Vasiliy Kulikov of Openwall discovered that the number
    of exit handlers that a process can register is not
    capped, resulting in local denial of service through
    resource exhaustion (CPU time and memory).

  - CVE-2011-2491
    Vasily Averin discovered an issue with the NFS locking
    implementation. A malicious NFS server can cause a
    client to hang indefinitely in an unlock call.

  - CVE-2011-2492
    Marek Kroemeke and Filip Palian discovered that
    uninitialized struct elements in the Bluetooth subsystem
    could lead to a leak of sensitive kernel memory through
    leaked stack memory.

  - CVE-2011-2495
    Vasiliy Kulikov of Openwall discovered that the io file
    of a process' proc directory was world-readable,
    resulting in local information disclosure of information
    such as password lengths.

  - CVE-2011-2496
    Robert Swiecki discovered that mremap() could be abused
    for local denial of service by triggering a BUG_ON
    assert.

  - CVE-2011-2497
    Dan Rosenberg discovered an integer underflow in the
    Bluetooth subsystem, which could lead to denial of
    service or privilege escalation.

  - CVE-2011-2525
    Ben Pfaff reported an issue in the network scheduling
    code. A local user could cause a denial of service (NULL
    pointer dereference) by sending a specially crafted
    netlink message.

  - CVE-2011-2928
    Timo Warns discovered that insufficient validation of Be
    filesystem images could lead to local denial of service
    if a malformed filesystem image is mounted.

  - CVE-2011-3188
    Dan Kaminsky reported a weakness of the sequence number
    generation in the TCP protocol implementation. This can
    be used by remote attackers to inject packets into an
    active session.

  - CVE-2011-3191
    Darren Lavender reported an issue in the Common Internet
    File System (CIFS). A malicious file server could cause
    memory corruption leading to a denial of service.

This update also includes a fix for a regression introduced with the
previous security fix for CVE-2011-1768 (Debian bug #633738)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=633738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2492"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=633738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2310"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux-2.6 and user-mode-linux packages. These updates will
not become active until after the system is rebooted.

For the oldstable distribution (lenny), this problem has been fixed in
version 2.6.26-26lenny4. Updates for arm and alpha are not yet
available, but will be released as soon as possible. Updates for the
hppa and ia64 architectures will be included in the upcoming 5.0.9
point release.

The following matrix lists additional source packages that were
rebuilt for compatibility with or to take advantage of this update :

                         Debian 5.0 (lenny)     
  user-mode-linux        2.6.26-1um-2+26lenny4  
Note: Debian carefully tracks all known security issues across every
linux kernel package in all releases under active security support.
However, given the high frequency at which low-severity security
issues are discovered in the kernel and the resource requirements of
doing an update, updates for lower priority issues will normally not
be released for all kernels at the same time. Rather, they will be
released in a staggered or 'leap-frog' fashion."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/26");
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
if (deb_check(release:"5.0", prefix:"linux-base", reference:"2.6.26-26lenny4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
