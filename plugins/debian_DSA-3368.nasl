#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3368. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86157);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/09/28 13:38:15 $");

  script_cve_id("CVE-2013-4122");
  script_xref(name:"DSA", value:"3368");

  script_name(english:"Debian DSA-3368-1 : cyrus-sasl2 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that cyrus-sasl2, a library implementing the Simple
Authentication and Security Layer, does not properly handle certain
invalid password salts. A remote attacker can take advantage of this
flaw to cause a denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=784112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/cyrus-sasl2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3368"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the cyrus-sasl2 packages.

For the stable distribution (jessie), this problem has been fixed in
version 2.1.26.dfsg1-13+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-sasl2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"cyrus-sasl2-dbg", reference:"2.1.26.dfsg1-13+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cyrus-sasl2-doc", reference:"2.1.26.dfsg1-13+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cyrus-sasl2-heimdal-dbg", reference:"2.1.26.dfsg1-13+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"cyrus-sasl2-mit-dbg", reference:"2.1.26.dfsg1-13+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsasl2-2", reference:"2.1.26.dfsg1-13+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsasl2-dev", reference:"2.1.26.dfsg1-13+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsasl2-modules", reference:"2.1.26.dfsg1-13+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsasl2-modules-db", reference:"2.1.26.dfsg1-13+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsasl2-modules-gssapi-heimdal", reference:"2.1.26.dfsg1-13+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsasl2-modules-gssapi-mit", reference:"2.1.26.dfsg1-13+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsasl2-modules-ldap", reference:"2.1.26.dfsg1-13+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsasl2-modules-otp", reference:"2.1.26.dfsg1-13+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsasl2-modules-sql", reference:"2.1.26.dfsg1-13+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"sasl2-bin", reference:"2.1.26.dfsg1-13+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
