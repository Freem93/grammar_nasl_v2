#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1947. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44812);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/05/17 23:54:23 $");

  script_cve_id("CVE-2009-3300");
  script_osvdb_id(59818);
  script_xref(name:"DSA", value:"1947");

  script_name(english:"Debian DSA-1947-1 : shibboleth-sp, shibboleth-sp2, opensaml2 - missing input sanitising");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Matt Elder discovered that Shibboleth, a federated web single sign-on
system is vulnerable to script injection through redirection URLs.
More details can be found in the Shibboleth advisory at
http://shibboleth.internet2.edu/secadv/secadv_20091104.txt."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://shibboleth.internet2.edu/secadv/secadv_20091104.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1947"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Shibboleth packages.

For the old stable distribution (etch), this problem has been fixed in
version 1.3f.dfsg1-2+etch2 of shibboleth-sp.

For the stable distribution (lenny), this problem has been fixed in
version 1.3.1.dfsg1-3+lenny2 of shibboleth-sp, version
2.0.dfsg1-4+lenny2 of shibboleth-sp2 and version 2.0-2+lenny2 of
opensaml2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:opensaml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:shibboleth-sp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:shibboleth-sp2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libapache2-mod-shib", reference:"1.3f.dfsg1-2+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libshib-dev", reference:"1.3f.dfsg1-2+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libshib-target5", reference:"1.3f.dfsg1-2+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libshib6", reference:"1.3f.dfsg1-2+etch2")) flag++;
if (deb_check(release:"5.0", prefix:"libapache2-mod-shib", reference:"1.3.1.dfsg1-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libapache2-mod-shib2", reference:"2.0.dfsg1-4+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libsaml2", reference:"2.0-2+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libsaml2-dev", reference:"2.0-2+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libsaml2-doc", reference:"2.0-2+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libshib-dev", reference:"1.3.1.dfsg1-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libshib-target5", reference:"1.3.1.dfsg1-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libshib6", reference:"1.3.1.dfsg1-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libshibsp-dev", reference:"2.0.dfsg1-4+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libshibsp-doc", reference:"2.0.dfsg1-4+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libshibsp1", reference:"2.0.dfsg1-4+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"opensaml2-schemas", reference:"2.0-2+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"opensaml2-tools", reference:"2.0-2+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"shibboleth-sp2-schemas", reference:"2.0.dfsg1-4+lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
