#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1538. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31808);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/26 15:53:37 $");

  script_cve_id("CVE-2007-5301");
  script_xref(name:"DSA", value:"1538");

  script_name(english:"Debian DSA-1538-1 : alsaplayer - buffer overrun");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Erik Sjolund discovered a buffer overflow vulnerability in the Ogg
Vorbis input plugin of the alsaplayer audio playback application.
Successful exploitation of this vulnerability through the opening of a
maliciously crafted Vorbis file could lead to the execution of
arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=446034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1538"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the alsaplayer packages.

For the stable distribution (etch), the problem has been fixed in
version 0.99.76-9+etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:alsaplayer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"alsaplayer-alsa", reference:"0.99.76-9+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"alsaplayer-common", reference:"0.99.76-9+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"alsaplayer-daemon", reference:"0.99.76-9+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"alsaplayer-esd", reference:"0.99.76-9+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"alsaplayer-gtk", reference:"0.99.76-9+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"alsaplayer-jack", reference:"0.99.76-9+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"alsaplayer-nas", reference:"0.99.76-9+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"alsaplayer-oss", reference:"0.99.76-9+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"alsaplayer-text", reference:"0.99.76-9+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"alsaplayer-xosd", reference:"0.99.76-9+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libalsaplayer-dev", reference:"0.99.76-9+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libalsaplayer0", reference:"0.99.76-9+etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
