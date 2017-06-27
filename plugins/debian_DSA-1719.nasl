#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1719. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35637);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/05/03 11:20:09 $");

  script_cve_id("CVE-2008-4989");
  script_xref(name:"DSA", value:"1719");

  script_name(english:"Debian DSA-1719-1 : gnutls13 - design flaw");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Martin von Gagern discovered that GNUTLS, an implementation of the
TLS/SSL protocol, handles verification of X.509 certificate chains
incorrectly if a self-signed certificate is configured as a trusted
certificate. This could cause clients to accept forged server
certificates as genuine. (CVE-2008-4989 )

In addition, this update tightens the checks for X.509v1 certificates
which causes GNUTLS to reject certain certificate chains it accepted
before. (In certificate chain processing, GNUTLS does not recognize
X.509v1 certificates as valid unless explicitly requested by the
application.)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=505360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1719"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gnutls13 packages.

For the stable distribution (etch), this problem has been fixed in
version 1.4.4-3+etch3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(255);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnutls13");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"gnutls-bin", reference:"1.4.4-3+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"gnutls-doc", reference:"1.4.4-3+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libgnutls-dev", reference:"1.4.4-3+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libgnutls13", reference:"1.4.4-3+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libgnutls13-dbg", reference:"1.4.4-3+etch3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
