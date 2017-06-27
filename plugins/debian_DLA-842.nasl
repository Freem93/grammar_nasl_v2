#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-842-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97439);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/03/20 15:44:32 $");

  script_cve_id("CVE-2017-2615", "CVE-2017-2620", "CVE-2017-5898", "CVE-2017-5973");
  script_osvdb_id(151241, 151566, 151974, 152349);
  script_xref(name:"IAVB", value:"2017-B-0024");

  script_name(english:"Debian DLA-842-1 : qemu-kvm security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in qemu-kvm, a full
virtualization solution for Linux hosts on x86 hardware with x86
guests.

CVE-2017-2615

The Cirrus CLGD 54xx VGA Emulator in qemu-kvm is vulnerable to an
out-of-bounds access issue. It could occur while copying VGA data via
bitblt copy in backward mode.

A privileged user inside guest could use this flaw to crash
the Qemu process resulting in DoS OR potentially execute
arbitrary code on the host with privileges of qemu-kvm
process on the host.

CVE-2017-2620

The Cirrus CLGD 54xx VGA Emulator in qemu-kvm is vulnerable to an
out-of-bounds access issue. It could occur while copying VGA data in
cirrus_bitblt_cputovideo.

A privileged user inside guest could use this flaw to crash
the Qemu process resulting in DoS OR potentially execute
arbitrary code on the host with privileges of qemu-kvm
process on the host.

CVE-2017-5898

The CCID Card device emulator support is vulnerable to an integer
overflow flaw. It could occur while passing message via
command/responses packets to and from the host.

A privileged user inside guest could use this flaw to crash
the qemu-kvm process on the host resulting in a DoS.

This issue does not affect the qemu-kvm binaries in Debian
but we apply the patch to the sources to stay in sync with
the qemu package.

CVE-2017-5973

The USB xHCI controller emulator support in qemu-kvm is vulnerable to
an infinite loop issue. It could occur while processing control
transfer descriptors' sequence in xhci_kick_epctx.

A privileged user inside guest could use this flaw to crash
the qemu-kvm process resulting in a DoS.

This update also updates the fix CVE-2016-9921 since it was too strict
and broke certain guests.

For Debian 7 'Wheezy', these problems have been fixed in version
1.1.2+dfsg-6+deb7u20.

We recommend that you upgrade your qemu-kvm packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/02/msg00033.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/qemu-kvm"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected kvm, qemu-kvm, and qemu-kvm-dbg packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-kvm-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/01");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (deb_check(release:"7.0", prefix:"kvm", reference:"1.1.2+dfsg-6+deb7u20")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-kvm", reference:"1.1.2+dfsg-6+deb7u20")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-kvm-dbg", reference:"1.1.2+dfsg-6+deb7u20")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
