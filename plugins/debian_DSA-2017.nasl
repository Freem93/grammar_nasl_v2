#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2017. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45062);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/05/17 23:54:24 $");

  script_cve_id("CVE-2009-1299");
  script_osvdb_id(63097);
  script_xref(name:"DSA", value:"2017");

  script_name(english:"Debian DSA-2017-1 : pulseaudio - insecure temporary directory");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Dan Rosenberg discovered that the PulseAudio sound server creates a
temporary directory with a predictable name. This allows a local
attacker to create a Denial of Service condition or possibly disclose
sensitive information to unprivileged users."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=573615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2017"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the pulseaudio package.

For the stable distribution (lenny), this problem has been fixed in
version 0.9.10-3+lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pulseaudio");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"libpulse-browse0", reference:"0.9.10-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libpulse-browse0-dbg", reference:"0.9.10-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libpulse-dev", reference:"0.9.10-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libpulse-mainloop-glib0", reference:"0.9.10-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libpulse-mainloop-glib0-dbg", reference:"0.9.10-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libpulse0", reference:"0.9.10-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libpulse0-dbg", reference:"0.9.10-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libpulsecore5", reference:"0.9.10-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libpulsecore5-dbg", reference:"0.9.10-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"pulseaudio", reference:"0.9.10-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"pulseaudio-dbg", reference:"0.9.10-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"pulseaudio-esound-compat", reference:"0.9.10-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"pulseaudio-esound-compat-dbg", reference:"0.9.10-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"pulseaudio-module-gconf", reference:"0.9.10-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"pulseaudio-module-gconf-dbg", reference:"0.9.10-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"pulseaudio-module-hal", reference:"0.9.10-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"pulseaudio-module-hal-dbg", reference:"0.9.10-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"pulseaudio-module-jack", reference:"0.9.10-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"pulseaudio-module-jack-dbg", reference:"0.9.10-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"pulseaudio-module-lirc", reference:"0.9.10-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"pulseaudio-module-lirc-dbg", reference:"0.9.10-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"pulseaudio-module-x11", reference:"0.9.10-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"pulseaudio-module-x11-dbg", reference:"0.9.10-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"pulseaudio-module-zeroconf", reference:"0.9.10-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"pulseaudio-module-zeroconf-dbg", reference:"0.9.10-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"pulseaudio-utils", reference:"0.9.10-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"pulseaudio-utils-dbg", reference:"0.9.10-3+lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
