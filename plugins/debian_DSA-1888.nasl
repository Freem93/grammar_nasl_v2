#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1888. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44753);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/05/03 11:20:10 $");

  script_cve_id("CVE-2009-2409");
  script_xref(name:"DSA", value:"1888");

  script_name(english:"Debian DSA-1888-1 : openssl, openssl097 - cryptographic weakness");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Certificates with MD2 hash signatures are no longer accepted by
OpenSSL, since they're no longer considered cryptographically secure."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1379"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1888"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssl packages.

For the stable distribution (lenny), this problem has been fixed in
version 0.9.8g-15+lenny5.

For the old stable distribution (etch), this problem has been fixed in
version 0.9.8c-4etch9 for openssl and version 0.9.7k-3.1etch5 for
openssl097. The OpenSSL 0.9.8 update for oldstable (etch) also
provides updated packages for multiple denial of service
vulnerabilities in the Datagram Transport Layer Security
implementation. These fixes were already provided for Debian stable
(Lenny) in a previous point update. The OpenSSL 0.9.7 package from
oldstable (Etch) is not affected. (CVE-2009-1377, CVE-2009-1378,
CVE-2009-1379, CVE-2009-1386 and CVE-2009-1387 )"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl097");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libssl-dev", reference:"0.9.8c-4etch9")) flag++;
if (deb_check(release:"4.0", prefix:"libssl0.9.7", reference:"0.9.7k-3.1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libssl0.9.7-dbg", reference:"0.9.7k-3.1etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libssl0.9.8", reference:"0.9.8c-4etch9")) flag++;
if (deb_check(release:"4.0", prefix:"libssl0.9.8-dbg", reference:"0.9.8c-4etch9")) flag++;
if (deb_check(release:"4.0", prefix:"openssl", reference:"0.9.8c-4etch9")) flag++;
if (deb_check(release:"5.0", prefix:"libssl-dev", reference:"0.9.8g-15+lenny5")) flag++;
if (deb_check(release:"5.0", prefix:"libssl0.9.8", reference:"0.9.8g-15+lenny5")) flag++;
if (deb_check(release:"5.0", prefix:"libssl0.9.8-dbg", reference:"0.9.8g-15+lenny5")) flag++;
if (deb_check(release:"5.0", prefix:"openssl", reference:"0.9.8g-15+lenny5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
