#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3112. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80230);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/16 15:48:48 $");

  script_cve_id("CVE-2014-8145");
  script_xref(name:"DSA", value:"3112");

  script_name(english:"Debian DSA-3112-1 : sox - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Michele Spagnuolo of the Google Security Team dicovered two heap-based
buffer overflows in SoX, the Swiss Army knife of sound processing
programs. A specially crafted wav file could cause an application
using SoX to crash or, possibly, execute arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=773720"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/sox"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-3112"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the sox packages.

For the stable distribution (wheezy), these problems have been fixed
in version 14.4.0-3+deb7u1.

For the upcoming stable distribution (jessie) and the unstable
distribution (sid), these problems will be fixed soon."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libsox-dev", reference:"14.4.0-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libsox-fmt-all", reference:"14.4.0-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libsox-fmt-alsa", reference:"14.4.0-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libsox-fmt-ao", reference:"14.4.0-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libsox-fmt-base", reference:"14.4.0-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libsox-fmt-ffmpeg", reference:"14.4.0-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libsox-fmt-mp3", reference:"14.4.0-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libsox-fmt-oss", reference:"14.4.0-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libsox-fmt-pulse", reference:"14.4.0-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libsox2", reference:"14.4.0-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"sox", reference:"14.4.0-3+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
