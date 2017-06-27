#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3499. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89005);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/10/10 14:14:52 $");

  script_cve_id("CVE-2016-0740", "CVE-2016-0775", "CVE-2016-2533");
  script_xref(name:"DSA", value:"3499");

  script_name(english:"Debian DSA-3499-1 : pillow - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security vulnerabilities have been found in Pillow, a Python
imaging library, which may result in denial of service or the
execution of arbitrary code if a malformed FLI, PCD or Tiff files is
processed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/pillow"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3499"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the pillow packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 1.1.7-4+deb7u2 of the python-imaging source package.

For the stable distribution (jessie), this problem has been fixed in
version 2.6.1-2+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pillow");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/29");
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
if (deb_check(release:"7.0", prefix:"pillow", reference:"1.1.7-4+deb7u2")) flag++;
if (deb_check(release:"8.0", prefix:"python-imaging", reference:"2.6.1-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python-imaging-tk", reference:"2.6.1-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python-pil", reference:"2.6.1-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python-pil-dbg", reference:"2.6.1-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python-pil-doc", reference:"2.6.1-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python-pil.imagetk", reference:"2.6.1-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python-pil.imagetk-dbg", reference:"2.6.1-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python-sane", reference:"2.6.1-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python-sane-dbg", reference:"2.6.1-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python3-pil", reference:"2.6.1-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python3-pil-dbg", reference:"2.6.1-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python3-pil.imagetk", reference:"2.6.1-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python3-pil.imagetk-dbg", reference:"2.6.1-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python3-sane", reference:"2.6.1-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python3-sane-dbg", reference:"2.6.1-2+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
