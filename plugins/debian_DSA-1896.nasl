#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1896. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44761);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/03/25 13:32:30 $");

  script_cve_id("CVE-2009-3474", "CVE-2009-3475");
  script_bugtraq_id(36514, 36516);
  script_osvdb_id(58378, 58392);
  script_xref(name:"DSA", value:"1896");

  script_name(english:"Debian DSA-1896-1 : opensaml, shibboleth-sp - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the opensaml and
shibboleth-sp packages, as used by Shibboleth 1.x :

  - Chris Ries discovered that decoding a crafted URL leads
    to a crash (and potentially, arbitrary code execution).
  - Ian Young discovered that embedded NUL characters in
    certificate names were not correctly handled, exposing
    configurations using PKIX trust validation to
    impersonation attacks.

  - Incorrect processing of SAML metadata ignored key usage
    constraints."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1896"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Shibboleth 1.x packages.

For the old stable distribution (etch), these problems have been fixed
in version 1.3f.dfsg1-2+etch1 of the shibboleth-sp packages, and
version 1.1a-2+etch1 of the opensaml packages.


For the stable distribution (lenny), these problems have been fixed in
version 1.3.1.dfsg1-3+lenny1 of the shibboleth-sp packages, and
version 1.1.1-2+lenny1 of the opensaml packages.

This update requires restarting the affected services (mainly Apache)
to become effective."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:opensaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:shibboleth-sp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libapache2-mod-shib", reference:"1.3f.dfsg1-2+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libsaml-dev", reference:"1.1a-2+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libsaml5", reference:"1.1a-2+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libshib-dev", reference:"1.3f.dfsg1-2+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libshib-target5", reference:"1.3f.dfsg1-2+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libshib6", reference:"1.3f.dfsg1-2+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"opensaml-schemas", reference:"1.1a-2+etch1")) flag++;
if (deb_check(release:"5.0", prefix:"libapache2-mod-shib", reference:"1.3.1.dfsg1-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libsaml-dev", reference:"1.1.1-2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libsaml5", reference:"1.1.1-2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libshib-dev", reference:"1.3.1.dfsg1-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libshib-target5", reference:"1.3.1.dfsg1-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libshib6", reference:"1.3.1.dfsg1-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"opensaml-schemas", reference:"1.1.1-2+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
