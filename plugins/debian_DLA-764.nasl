#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-764-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96099);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/01/03 14:55:08 $");

  script_cve_id("CVE-2016-9911", "CVE-2016-9921", "CVE-2016-9922");
  script_osvdb_id(148375, 148394);

  script_name(english:"Debian DLA-764-1 : qemu security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been found in QEMU :

CVE-2016-9911

Quick Emulator (Qemu) built with the USB EHCI Emulation support is
vulnerable to a memory leakage issue. It could occur while processing
packet data in 'ehci_init_transfer'. A guest user/ process could use
this issue to leak host memory, resulting in DoS for a host.

CVE-2016-9921, CVE-2016-9922

Quick emulator (Qemu) built with the Cirrus CLGD 54xx VGA Emulator
support is vulnerable to a divide by zero issue. It could occur while
copying VGA data when cirrus graphics mode was set to be VGA. A
privileged user inside guest could use this flaw to crash the Qemu
process instance on the host, resulting in DoS.

For Debian 7 'Wheezy', these problems have been fixed in version
1.1.2+dfsg-6+deb7u19.

We recommend that you upgrade your qemu packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/12/msg00040.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/qemu"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-keymaps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-user-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"qemu", reference:"1.1.2+dfsg-6+deb7u19")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-keymaps", reference:"1.1.2+dfsg-6+deb7u19")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-system", reference:"1.1.2+dfsg-6+deb7u19")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-user", reference:"1.1.2+dfsg-6+deb7u19")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-user-static", reference:"1.1.2+dfsg-6+deb7u19")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-utils", reference:"1.1.2+dfsg-6+deb7u19")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
