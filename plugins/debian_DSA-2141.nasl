#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2141. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51440);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/05/03 11:20:11 $");

  script_cve_id("CVE-2009-3555", "CVE-2010-4180");
  script_bugtraq_id(36935, 45164);
  script_xref(name:"DSA", value:"2141");

  script_name(english:"Debian DSA-2141-1 : openssl - SSL/TLS insecure renegotiation protocol design flaw");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"DSA-2141 consists of three individual parts, which can be viewed in
the mailing list archive: DSA 2141-1 (openssl), DSA 2141-2 (nss), DSA
2141-3 (apache2), and DSA 2141-4 (lighttpd). This page only covers the
first part, openssl.

  - CVE-2009-3555
    Marsh Ray, Steve Dispensa, and Martin Rex discovered a
    flaw in the TLS and SSLv3 protocols. If an attacker
    could perform a man in the middle attack at the start of
    a TLS connection, the attacker could inject arbitrary
    content at the beginning of the user's session. This
    update adds backported support for the new RFC5746
    renegotiation extension which fixes this issue.

  If openssl is used in a server application, it will by default no
  longer accept renegotiation from clients that do not support the
  RFC5746 secure renegotiation extension. A separate advisory will add
  RFC5746 support for nss, the security library used by the iceweasel
  web browser. For apache2, there will be an update which allows to
  re-enable insecure renegotiation.

  This version of openssl is not compatible with older versions of
  tor. You have to use at least tor version 0.2.1.26-1~lenny+1, which
  has been included in the point release 5.0.7 of Debian stable.

  Currently we are not aware of other software with similar
  compatibility problems.

  - CVE-2010-4180
    In addition, this update fixes a flaw that allowed a
    client to bypass restrictions configured in the server
    for the used cipher suite."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=555829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-security-announce/2011/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-security-announce/2011/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-security-announce/2011/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-security-announce/2011/msg00006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2141"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssl package.

For the stable distribution (lenny), this problem has been fixed in
version 0.9.8g-15+lenny11."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"openssl", reference:"0.9.8g-15+lenny11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
