#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3589. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91366);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/06 20:25:09 $");

  script_cve_id("CVE-2015-7552", "CVE-2015-8875");
  script_osvdb_id(133603, 138541);
  script_xref(name:"DSA", value:"3589");

  script_name(english:"Debian DSA-3589-1 : gdk-pixbuf - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in gdk-pixbuf, a toolkit
for image loading and pixel buffer manipulation. A remote attacker can
take advantage of these flaws to cause a denial-of-service against an
application using gdk-pixbuf (application crash), or potentially, to
execute arbitrary code with the privileges of the user running the
application, if a malformed image is opened."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/gdk-pixbuf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3589"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gdk-pixbuf packages.

For the stable distribution (jessie), these problems have been fixed
in version 2.31.1-2+deb8u5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gdk-pixbuf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"gir1.2-gdkpixbuf-2.0", reference:"2.31.1-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libgdk-pixbuf2.0-0", reference:"2.31.1-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libgdk-pixbuf2.0-0-dbg", reference:"2.31.1-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libgdk-pixbuf2.0-common", reference:"2.31.1-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libgdk-pixbuf2.0-dev", reference:"2.31.1-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libgdk-pixbuf2.0-doc", reference:"2.31.1-2+deb8u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
