#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-246-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(84252);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2016/12/06 20:03:51 $");

  script_cve_id("CVE-2011-5321", "CVE-2012-6689", "CVE-2014-3184", "CVE-2014-8159", "CVE-2014-9683", "CVE-2014-9728", "CVE-2014-9729", "CVE-2014-9730", "CVE-2014-9731", "CVE-2015-1805", "CVE-2015-2041", "CVE-2015-2042", "CVE-2015-2830", "CVE-2015-2922", "CVE-2015-3339", "CVE-2015-4167");
  script_bugtraq_id(69768, 72643, 72729, 72730, 72739, 73060, 73141, 73699, 74243, 74315, 74951, 74963, 74964, 75001);
  script_osvdb_id(110567, 110568, 110569, 110570, 110571, 110572, 118083, 118625, 118655, 118659, 119615, 119630, 119797, 120282, 120284, 121170, 122921, 122965, 122966, 122967, 122968);

  script_name(english:"Debian DLA-246-2 : linux-2.6 regression update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The linux-2.6 update issued as DLA-246-1 caused regressions. This
update corrects the defective patches applied in that update causing
these problems. For reference the original advisory text follows.

This update fixes the CVEs described below.

CVE-2011-5321

Jiri Slaby discovered that tty_driver_lookup_tty() may leak a
reference to the tty driver. A local user could use this flaw to crash
the system.

CVE-2012-6689

Pablo Neira Ayuso discovered that non-root user-space processes can
send forged Netlink notifications to other processes. A local user
could use this flaw for denial of service or privilege escalation.

CVE-2014-3184

Ben Hawkes discovered that various HID drivers may over-read the
report descriptor buffer, possibly resulting in a crash if a HID with
a crafted descriptor is plugged in.

CVE-2014-8159

It was found that the Linux kernel's InfiniBand/RDMA subsystem did not
properly sanitize input parameters while registering memory regions
from user space via the (u)verbs API. A local user with access to a
/dev/infiniband/uverbsX device could use this flaw to crash the system
or, potentially, escalate their privileges on the system.

CVE-2014-9683

Dmitry Chernenkov discovered that eCryptfs writes past the end of the
allocated buffer during encrypted filename decoding, resulting in
local denial of service.

CVE-2014-9728 / CVE-2014-9729 / CVE-2014-9730 / CVE-2014-9731 /
CVE-2015-4167

Carl Henrik Lunde discovered that the UDF implementation is missing
several necessary length checks. A local user that can mount devices
could use these various flaws to crash the system, to leak information
from the kernel, or possibly for privilege escalation.

CVE-2015-1805

Red Hat discovered that the pipe iovec read and write implementations
may iterate over the iovec twice but will modify the iovec such that
the second iteration accesses the wrong memory. A local user could use
this flaw to crash the system or possibly for privilege escalation.
This may also result in data corruption and information leaks in pipes
between non-malicious processes.

CVE-2015-2041

Sasha Levin discovered that the LLC subsystem exposed some variables
as sysctls with the wrong type. On a 64-bit kernel, this possibly
allows privilege escalation from a process with CAP_NET_ADMIN
capability; it also results in a trivial information leak.

CVE-2015-2042

Sasha Levin discovered that the RDS subsystem exposed some variables
as sysctls with the wrong type. On a 64-bit kernel, this results in a
trivial information leak.

CVE-2015-2830

Andrew Lutomirski discovered that when a 64-bit task on an amd64
kernel makes a fork(2) or clone(2) system call using int $0x80, the
32-bit compatibility flag is set (correctly) but is not cleared on
return. As a result, both seccomp and audit will misinterpret the
following system call by the task(s), possibly leading to a violation
of security policy.

CVE-2015-2922

Modio AB discovered that the IPv6 subsystem would process a router
advertisement that specifies no route but only a hop limit, which
would then be applied to the interface that received it. This can
result in loss of IPv6 connectivity beyond the local network.

This may be mitigated by disabling processing of IPv6 router
advertisements if they are not needed: sysctl
net.ipv6.conf.default.accept_ra=0 sysctl
net.ipv6.conf.<interface>.accept_ra=0

CVE-2015-3339

It was found that the execve(2) system call can race with inode
attribute changes made by chown(2). Although chown(2) clears the
setuid/setgid bits of a file if it changes the respective owner ID,
this race condition could result in execve(2) setting effective
uid/gid to the new owner ID, a privilege escalation.

For the oldoldstable distribution (squeeze), these problems have been
fixed in version 2.6.32-48squeeze12.

For the oldstable distribution (wheezy), these problems were fixed in
linux version 3.2.68-1+deb7u1 or earlier, except for CVE-2015-1805 and
CVE-2015-4167 which will be fixed soon.

For the stable distribution (jessie), these problems were fixed in
linux version 3.16.7-ckt11-1 or earlier, except for CVE-2015-4167
which will be fixed later.

We recommend that you upgrade your linux-2.6 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/06/msg00012.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/linux-2.6"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-linux-free");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-2.6.32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-486");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-686-bigmem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-all-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-all-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-common-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-common-vserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-common-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-openvz-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-openvz-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-vserver-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-vserver-686-bigmem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-vserver-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-xen-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-2.6.32-5-xen-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-486");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-686-bigmem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-686-bigmem-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-openvz-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-openvz-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-openvz-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-openvz-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-vserver-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-vserver-686-bigmem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-vserver-686-bigmem-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-vserver-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-vserver-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-xen-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-xen-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-xen-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-2.6.32-5-xen-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-manual-2.6.32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-patch-debian-2.6.32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-2.6.32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-2.6.32-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-tools-2.6.32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-linux-system-2.6.32-5-xen-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-linux-system-2.6.32-5-xen-amd64");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"firmware-linux-free", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-base", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-doc-2.6.32", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-486", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-686", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-686-bigmem", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-amd64", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-all-i386", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-amd64", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common-openvz", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common-vserver", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-common-xen", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-openvz-686", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-openvz-amd64", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-686", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-686-bigmem", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-vserver-amd64", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-xen-686", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-headers-2.6.32-5-xen-amd64", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-486", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-686", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-686-bigmem", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-686-bigmem-dbg", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-amd64", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-amd64-dbg", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-686", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-686-dbg", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-amd64", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-openvz-amd64-dbg", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-686", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-686-bigmem", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-686-bigmem-dbg", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-amd64", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-vserver-amd64-dbg", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-686", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-686-dbg", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-amd64", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-image-2.6.32-5-xen-amd64-dbg", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-libc-dev", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-manual-2.6.32", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-patch-debian-2.6.32", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-source-2.6.32", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-support-2.6.32-5", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"linux-tools-2.6.32", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"xen-linux-system-2.6.32-5-xen-686", reference:"2.6.32-48squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"xen-linux-system-2.6.32-5-xen-amd64", reference:"2.6.32-48squeeze13")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
