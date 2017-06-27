#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2704. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66847);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/16 15:43:09 $");

  script_cve_id("CVE-2013-1872");
  script_bugtraq_id(60285);
  script_xref(name:"DSA", value:"2704");

  script_name(english:"Debian DSA-2704-1 : mesa - out of bounds access");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that applications using the mesa library, a free
implementation of the OpenGL API, may crash or execute arbitrary code
due to an out of bounds memory access in the library. This
vulnerability only affects systems with Intel chipsets.

The oldstable distribution (squeeze) is not affected by this problem."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/mesa"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2704"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mesa packages.

For the stable distribution (wheezy), this problem has been fixed in
version 8.0.5-4+deb7u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mesa");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libegl1-mesa", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libegl1-mesa-dbg", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libegl1-mesa-dev", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libegl1-mesa-drivers", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libegl1-mesa-drivers-dbg", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libgbm-dev", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libgbm1", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libgbm1-dbg", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libgl1-mesa-dev", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libgl1-mesa-dri", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libgl1-mesa-dri-dbg", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libgl1-mesa-dri-experimental", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libgl1-mesa-dri-experimental-dbg", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libgl1-mesa-glx", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libgl1-mesa-glx-dbg", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libgl1-mesa-swx11", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libgl1-mesa-swx11-dbg", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libgl1-mesa-swx11-dev", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libgl1-mesa-swx11-i686", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libglapi-mesa", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libglapi-mesa-dbg", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libgles1-mesa", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libgles1-mesa-dbg", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libgles1-mesa-dev", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libgles2-mesa", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libgles2-mesa-dbg", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libgles2-mesa-dev", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libglu1-mesa", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libglu1-mesa-dev", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libopenvg1-mesa", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libopenvg1-mesa-dbg", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libopenvg1-mesa-dev", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libosmesa6", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libosmesa6-dev", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libxatracker-dev", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libxatracker1", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libxatracker1-dbg", reference:"8.0.5-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"mesa-common-dev", reference:"8.0.5-4+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
