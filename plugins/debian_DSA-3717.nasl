#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3717. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94942);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/11/22 15:29:15 $");

  script_xref(name:"DSA", value:"3717");

  script_name(english:"Debian DSA-3717-1 : gst-plugins-bad1.0, gst-plugins-bad0.10 - security update");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chris Evans discovered that the GStreamer plugin to decode VMware
screen capture files allowed the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/gst-plugins-bad1.0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/gst-plugins-bad0.10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3717"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gst-plugins-bad1.0 packages.

For the stable distribution (jessie), this problem has been fixed in
version 1.4.4-2.1+deb8u1 of gst-plugins-bad1.0 and version
0.10.23-7.4+deb8u2 of gst-plugins-bad0.10."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gst-plugins-bad0.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gst-plugins-bad1.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/18");
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
if (deb_check(release:"8.0", prefix:"gstreamer0.10-plugins-bad", reference:"0.10.23-7.4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"gstreamer0.10-plugins-bad-dbg", reference:"0.10.23-7.4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"gstreamer1.0-plugins-bad", reference:"1.4.4-2.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gstreamer1.0-plugins-bad-dbg", reference:"1.4.4-2.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gstreamer1.0-plugins-bad-doc", reference:"1.4.4-2.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgstreamer-plugins-bad0.10-0", reference:"0.10.23-7.4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgstreamer-plugins-bad0.10-dev", reference:"0.10.23-7.4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgstreamer-plugins-bad1.0-0", reference:"1.4.4-2.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgstreamer-plugins-bad1.0-dev", reference:"1.4.4-2.1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
