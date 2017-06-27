#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3286. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84169);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/05/05 16:01:12 $");

  script_cve_id("CVE-2015-3209", "CVE-2015-4103", "CVE-2015-4104", "CVE-2015-4105", "CVE-2015-4106", "CVE-2015-4163", "CVE-2015-4164");
  script_bugtraq_id(74947, 74948, 74949, 74950, 75123, 75141, 75149);
  script_osvdb_id(122855, 122856, 122857, 122858, 123147, 123237, 123281);
  script_xref(name:"DSA", value:"3286");

  script_name(english:"Debian DSA-3286-1 : xen - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues have been found in the Xen virtualisation
solution :

  - CVE-2015-3209
    Matt Tait discovered a flaw in the way QEMU's AMD PCnet
    Ethernet emulation handles multi-TMD packets with a
    length above 4096 bytes. A privileged guest user in a
    guest with an AMD PCNet ethernet card enabled can
    potentially use this flaw to execute arbitrary code on
    the host with the privileges of the hosting QEMU
    process.

  - CVE-2015-4103
    Jan Beulich discovered that the QEMU Xen code does not
    properly restrict write access to the host MSI message
    data field, allowing a malicious guest to cause a denial
    of service.

  - CVE-2015-4104
    Jan Beulich discovered that the QEMU Xen code does not
    properly restrict access to PCI MSI mask bits, allowing
    a malicious guest to cause a denial of service.

  - CVE-2015-4105
    Jan Beulich reported that the QEMU Xen code enables
    logging for PCI MSI-X pass-through error messages,
    allowing a malicious guest to cause a denial of service.

  - CVE-2015-4106
    Jan Beulich discovered that the QEMU Xen code does not
    properly restrict write access to the PCI config space
    for certain PCI pass-through devices, allowing a
    malicious guest to cause a denial of service, obtain
    sensitive information or potentially execute arbitrary
    code.

  - CVE-2015-4163
    Jan Beulich discovered that a missing version check in
    the GNTTABOP_swap_grant_ref hypercall handler may result
    in denial of service. This only applies to Debian
    stable/jessie.

  - CVE-2015-4164
    Andrew Cooper discovered a vulnerability in the iret
    hypercall handler, which may result in denial of
    service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/xen"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/xen"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3286"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xen packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 4.1.4-3+deb7u8. 

For the stable distribution (jessie), these problems have been fixed
in version 4.4.1-9+deb8u1. CVE-2015-3209, CVE-2015-4103,
CVE-2015-4104, CVE-2015-4105 and CVE-2015-4106 don't affect the Xen
package in stable jessie, it uses the standard qemu package and has
already been fixed in DSA-3284-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/15");
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
if (deb_check(release:"7.0", prefix:"libxen-4.1", reference:"4.1.4-3+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-dev", reference:"4.1.4-3+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-ocaml", reference:"4.1.4-3+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-ocaml-dev", reference:"4.1.4-3+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libxenstore3.0", reference:"4.1.4-3+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"xen-docs-4.1", reference:"4.1.4-3+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"xen-hypervisor-4.1-amd64", reference:"4.1.4-3+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"xen-hypervisor-4.1-i386", reference:"4.1.4-3+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"xen-system-amd64", reference:"4.1.4-3+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"xen-system-i386", reference:"4.1.4-3+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"xen-utils-4.1", reference:"4.1.4-3+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"xen-utils-common", reference:"4.1.4-3+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"xenstore-utils", reference:"4.1.4-3+deb7u8")) flag++;
if (deb_check(release:"8.0", prefix:"libxen-4.4", reference:"4.4.1-9+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libxen-dev", reference:"4.4.1-9+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libxenstore3.0", reference:"4.4.1-9+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xen-hypervisor-4.4-amd64", reference:"4.4.1-9+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xen-hypervisor-4.4-arm64", reference:"4.4.1-9+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xen-hypervisor-4.4-armhf", reference:"4.4.1-9+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xen-system-amd64", reference:"4.4.1-9+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xen-system-arm64", reference:"4.4.1-9+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xen-system-armhf", reference:"4.4.1-9+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xen-utils-4.4", reference:"4.4.1-9+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xen-utils-common", reference:"4.4.1-9+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xenstore-utils", reference:"4.4.1-9+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
