#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-368-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87330);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/04/28 18:23:47 $");

  script_cve_id("CVE-2015-8370");
  script_osvdb_id(131484);

  script_name(english:"Debian DLA-368-1 : grub2 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Hector Marco-Gisbert, from the Universitat Polit&egrave;cnica de
Val&egrave;ncia Cybersecurity Team, reported a buffer overflow in
grub2 when checking password during bootup.

For Debian 6 'Squeeze', this problem has been fixed in grub2 version
1.98+20100804-14+squeeze2. We recommend you to upgrade your grub2
packages.

Learn more about the Debian Long Term Support (LTS) Project and how to
apply these updates at: https://wiki.debian.org/LTS/

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/12/msg00009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/grub2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.debian.org/LTS/"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-coreboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-efi-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-efi-ia32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-emu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-firmware-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-ieee1275");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-linuxbios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub-rescue-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:grub2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/14");
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
if (deb_check(release:"6.0", prefix:"grub-common", reference:"1.98+20100804-14+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"grub-coreboot", reference:"1.98+20100804-14+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"grub-efi", reference:"1.98+20100804-14+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"grub-efi-amd64", reference:"1.98+20100804-14+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"grub-efi-ia32", reference:"1.98+20100804-14+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"grub-emu", reference:"1.98+20100804-14+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"grub-firmware-qemu", reference:"1.98+20100804-14+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"grub-ieee1275", reference:"1.98+20100804-14+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"grub-linuxbios", reference:"1.98+20100804-14+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"grub-pc", reference:"1.98+20100804-14+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"grub-rescue-pc", reference:"1.98+20100804-14+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"grub2", reference:"1.98+20100804-14+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
