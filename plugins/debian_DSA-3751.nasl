#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3751. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96195);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/01/10 18:05:23 $");

  script_cve_id("CVE-2016-9933");
  script_xref(name:"DSA", value:"3751");

  script_name(english:"Debian DSA-3751-1 : libgd2 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A stack overflow vulnerability was discovered within the
gdImageFillToBorder function in libgd2, a library for programmatic
graphics creation and manipulation, triggered when invalid colors are
used with truecolor images. A remote attacker can take advantage of
this flaw to cause a denial-of-service against an application using
the libgd2 library."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=849038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libgd2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2017/dsa-3751"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libgd2 packages.

For the stable distribution (jessie), this problem has been fixed in
version 2.1.0-5+deb8u8."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgd2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"libgd-dbg", reference:"2.1.0-5+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libgd-dev", reference:"2.1.0-5+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libgd-tools", reference:"2.1.0-5+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libgd2-noxpm-dev", reference:"2.1.0-5+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libgd2-xpm-dev", reference:"2.1.0-5+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"libgd3", reference:"2.1.0-5+deb8u8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
