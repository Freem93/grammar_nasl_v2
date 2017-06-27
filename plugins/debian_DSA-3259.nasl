#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3259. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83422);
  script_version("$Revision: 2.22 $");
  script_cvs_date("$Date: 2016/12/07 14:59:56 $");

  script_cve_id("CVE-2014-9718", "CVE-2015-1779", "CVE-2015-2756", "CVE-2015-3456");
  script_bugtraq_id(72577, 73303, 73316);
  script_osvdb_id(119885, 120062, 120289, 122072);
  script_xref(name:"DSA", value:"3259");
  script_xref(name:"IAVA", value:"2015-A-0115");

  script_name(english:"Debian DSA-3259-1 : qemu - security update (Venom)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in the qemu virtualisation
solution :

  - CVE-2014-9718
    It was discovered that the IDE controller emulation is
    susceptible to denial of service.

  - CVE-2015-1779
    Daniel P. Berrange discovered a denial of service
    vulnerability in the VNC web socket decoder.

  - CVE-2015-2756
    Jan Beulich discovered that unmediated PCI command
    register could result in denial of service.

  - CVE-2015-3456
    Jason Geffner discovered a buffer overflow in the
    emulated floppy disk drive, resulting in the potential
    execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9718"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-2756"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/qemu"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/qemu"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3259"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the qemu packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 1.1.2+dfsg-6a+deb7u7 of the qemu source package and
in version 1.1.2+dfsg-6+deb7u7 of the qemu-kvm source package. Only
CVE-2015-3456 affects oldstable.

For the stable distribution (jessie), these problems have been fixed
in version 1:2.1+dfsg-12."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/13");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/13");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if (deb_check(release:"7.0", prefix:"qemu", reference:"1.1.2+dfsg-6a+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-keymaps", reference:"1.1.2+dfsg-6a+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-system", reference:"1.1.2+dfsg-6a+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-user", reference:"1.1.2+dfsg-6a+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-user-static", reference:"1.1.2+dfsg-6a+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-utils", reference:"1.1.2+dfsg-6a+deb7u7")) flag++;
if (deb_check(release:"8.0", prefix:"qemu", reference:"1:2.1+dfsg-12")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-guest-agent", reference:"1:2.1+dfsg-12")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-kvm", reference:"1:2.1+dfsg-12")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system", reference:"1:2.1+dfsg-12")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-arm", reference:"1:2.1+dfsg-12")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-common", reference:"1:2.1+dfsg-12")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-mips", reference:"1:2.1+dfsg-12")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-misc", reference:"1:2.1+dfsg-12")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-ppc", reference:"1:2.1+dfsg-12")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-sparc", reference:"1:2.1+dfsg-12")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-x86", reference:"1:2.1+dfsg-12")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-user", reference:"1:2.1+dfsg-12")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-user-binfmt", reference:"1:2.1+dfsg-12")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-user-static", reference:"1:2.1+dfsg-12")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-utils", reference:"1:2.1+dfsg-12")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
