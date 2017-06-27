#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1461. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29938);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/05/17 23:45:45 $");

  script_cve_id("CVE-2007-6284");
  script_osvdb_id(40194);
  script_xref(name:"DSA", value:"1461");

  script_name(english:"Debian DSA-1461-1 : libxml2 - missing input validation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Brad Fitzpatrick discovered that the UTF-8 decoding functions of
libxml2, the GNOME XML library, validate UTF-8 correctness
insufficiently, which may lead to denial of service by forcing libxml2
into an infinite loop."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1461"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libxml2 packages.

For the old stable distribution (sarge), this problem has been fixed
in version 2.6.16-7sarge1.

For the stable distribution (etch), this problem has been fixed in
version 2.6.27.dfsg-2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/14");
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
if (deb_check(release:"3.1", prefix:"libxml2", reference:"2.6.16-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libxml2-dev", reference:"2.6.16-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libxml2-doc", reference:"2.6.16-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libxml2-python2.3", reference:"2.6.16-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libxml2-utils", reference:"2.6.16-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"python-libxml2", reference:"2.6.16-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"python2.2-libxml2", reference:"2.6.16-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"python2.3-libxml2", reference:"2.6.16-7sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"python2.4-libxml2", reference:"2.6.16-7sarge1")) flag++;
if (deb_check(release:"4.0", prefix:"libxml2", reference:"2.6.27.dfsg-2")) flag++;
if (deb_check(release:"4.0", prefix:"libxml2-dbg", reference:"2.6.27.dfsg-2")) flag++;
if (deb_check(release:"4.0", prefix:"libxml2-dev", reference:"2.6.27.dfsg-2")) flag++;
if (deb_check(release:"4.0", prefix:"libxml2-doc", reference:"2.6.27.dfsg-2")) flag++;
if (deb_check(release:"4.0", prefix:"libxml2-utils", reference:"2.6.27.dfsg-2")) flag++;
if (deb_check(release:"4.0", prefix:"python-libxml2", reference:"2.6.27.dfsg-2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
