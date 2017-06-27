#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3736. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96015);
  script_version("$Revision: 3.6 $");
  script_cvs_date("$Date: 2017/03/27 13:24:14 $");

  script_cve_id("CVE-2016-6255", "CVE-2016-8863");
  script_xref(name:"DSA", value:"3736");
  script_xref(name:"TRA", value:"TRA-2017-10");

  script_name(english:"Debian DSA-3736-1 : libupnp - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were discovered in libupnp, a portable SDK for
UPnP devices.

  - CVE-2016-6255
    Matthew Garret discovered that libupnp by default allows
    any user to write to the filesystem of the host running
    a libupnp-based server application.

  - CVE-2016-8863
    Scott Tenaglia discovered a heap buffer overflow
    vulnerability, that can lead to denial of service or
    remote code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=831857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=842093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-6255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-8863"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libupnp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3736"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2017-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libupnp packages.

For the stable distribution (jessie), these problems have been fixed
in version 1:1.6.19+git20141001-1+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libupnp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"libupnp-dev", reference:"1:1.6.19+git20141001-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libupnp6", reference:"1:1.6.19+git20141001-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libupnp6-dbg", reference:"1:1.6.19+git20141001-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libupnp6-dev", reference:"1:1.6.19+git20141001-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libupnp6-doc", reference:"1:1.6.19+git20141001-1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
