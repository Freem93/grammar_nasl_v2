#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1763. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36090);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/05 14:49:55 $");

  script_cve_id("CVE-2009-0590");
  script_bugtraq_id(34256);
  script_xref(name:"DSA", value:"1763");

  script_name(english:"Debian DSA-1763-1 : openssl - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that insufficient length validations in the ASN.1
handling of the OpenSSL crypto library may lead to denial of service
when processing a manipulated certificate."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1763"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssl packages.

For the old stable distribution (etch), this problem has been fixed in
version 0.9.8c-4etch5 of the openssl package and in version
0.9.7k-3.1etch3 of the openssl097 package.

For the stable distribution (lenny), this problem has been fixed in
version 0.9.8g-15+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libssl-dev", reference:"0.9.8c-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libssl0.9.7", reference:"0.9.7k-3.1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libssl0.9.7-dbg", reference:"0.9.7k-3.1etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libssl0.9.8", reference:"0.9.8c-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libssl0.9.8-dbg", reference:"0.9.8c-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"openssl", reference:"0.9.8c-4etch5")) flag++;
if (deb_check(release:"5.0", prefix:"libssl-dev", reference:"0.9.8g-15+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libssl0.9.8", reference:"0.9.8g-15+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libssl0.9.8-dbg", reference:"0.9.8g-15+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"openssl", reference:"0.9.8g-15+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
