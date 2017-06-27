#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3421. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87428);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/04/28 18:33:24 $");

  script_cve_id("CVE-2015-8370");
  script_osvdb_id(131484);
  script_xref(name:"DSA", value:"3421");

  script_name(english:"Debian DSA-3421-1 : grub2 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Hector Marco and Ismael Ripoll, from Cybersecurity UPV Research Group,
found an integer underflow vulnerability in Grub2, a popular
bootloader. A local attacker can bypass the Grub2 authentication by
inserting a crafted input as username or password.

More information:
http://hmarco.org/bugs/CVE-2015-8370-Grub2-authentication-bypass.html
CVE-2015-8370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=807614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://hmarco.org/bugs/CVE-2015-8370-Grub2-authentication-bypass.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/grub2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/grub2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3421"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the grub2 packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 1.99-27+deb7u3.

For the stable distribution (jessie), this problem has been fixed in
version 2.02~beta2-22+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/17");
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
if (deb_check(release:"7.0", prefix:"grub-common", reference:"1.99-27+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"grub-coreboot", reference:"1.99-27+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"grub-coreboot-bin", reference:"1.99-27+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"grub-efi", reference:"1.99-27+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"grub-efi-amd64", reference:"1.99-27+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"grub-efi-amd64-bin", reference:"1.99-27+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"grub-efi-ia32", reference:"1.99-27+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"grub-efi-ia32-bin", reference:"1.99-27+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"grub-emu", reference:"1.99-27+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"grub-firmware-qemu", reference:"1.99-27+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"grub-ieee1275", reference:"1.99-27+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"grub-ieee1275-bin", reference:"1.99-27+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"grub-linuxbios", reference:"1.99-27+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"grub-pc", reference:"1.99-27+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"grub-pc-bin", reference:"1.99-27+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"grub-rescue-pc", reference:"1.99-27+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"grub-yeeloong", reference:"1.99-27+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"grub-yeeloong-bin", reference:"1.99-27+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"grub2", reference:"1.99-27+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"grub2-common", reference:"1.99-27+deb7u3")) flag++;
if (deb_check(release:"8.0", prefix:"grub-common", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-coreboot", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-coreboot-bin", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-coreboot-dbg", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-efi", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-efi-amd64", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-efi-amd64-bin", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-efi-amd64-dbg", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-efi-arm", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-efi-arm-bin", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-efi-arm-dbg", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-efi-arm64", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-efi-arm64-bin", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-efi-arm64-dbg", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-efi-ia32", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-efi-ia32-bin", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-efi-ia32-dbg", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-emu", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-emu-dbg", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-firmware-qemu", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-ieee1275", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-ieee1275-bin", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-ieee1275-dbg", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-linuxbios", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-pc", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-pc-bin", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-pc-dbg", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-rescue-pc", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-theme-starfield", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-uboot", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-uboot-bin", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-uboot-dbg", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-xen", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-xen-bin", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-xen-dbg", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-xen-host", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-yeeloong", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-yeeloong-bin", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub-yeeloong-dbg", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub2", reference:"2.02~beta2-22+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"grub2-common", reference:"2.02~beta2-22+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
