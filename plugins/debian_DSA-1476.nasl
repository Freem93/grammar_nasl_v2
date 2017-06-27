#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1476. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30111);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/05/17 23:45:45 $");

  script_cve_id("CVE-2008-0008");
  script_osvdb_id(42842);
  script_xref(name:"DSA", value:"1476");

  script_name(english:"Debian DSA-1476-1 : pulseaudio - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Marcus Meissner discovered that the PulseAudio sound server performed
insufficient checks when dropping privileges, which could lead to
local privilege escalation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1476"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the pulseaudio packages.

The old stable distribution (sarge) doesn't contain pulseaudio.

For the stable distribution (etch), this problem has been fixed in
version 0.9.5-5etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pulseaudio");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libpulse-browse0", reference:"0.9.5-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libpulse-dev", reference:"0.9.5-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libpulse-mainloop-glib0", reference:"0.9.5-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libpulse0", reference:"0.9.5-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"pulseaudio", reference:"0.9.5-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"pulseaudio-esound-compat", reference:"0.9.5-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"pulseaudio-module-gconf", reference:"0.9.5-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"pulseaudio-module-hal", reference:"0.9.5-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"pulseaudio-module-jack", reference:"0.9.5-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"pulseaudio-module-lirc", reference:"0.9.5-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"pulseaudio-module-x11", reference:"0.9.5-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"pulseaudio-module-zeroconf", reference:"0.9.5-5etch1")) flag++;
if (deb_check(release:"4.0", prefix:"pulseaudio-utils", reference:"0.9.5-5etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
