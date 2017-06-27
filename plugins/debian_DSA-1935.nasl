#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1935. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44800);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:49:56 $");

  script_cve_id("CVE-2009-2409", "CVE-2009-2730");
  script_bugtraq_id(35952);
  script_osvdb_id(56752, 56960);
  script_xref(name:"DSA", value:"1935");

  script_name(english:"Debian DSA-1935-1 : gnutls13 gnutls26 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Dan Kaminsky and Moxie Marlinspike discovered that gnutls, an
implementation of the TLS/SSL protocol, does not properly handle a
'\0' character in a domain name in the subject's Common Name or
Subject Alternative Name (SAN) field of an X.509 certificate, which
allows man-in-the-middle attackers to spoof arbitrary SSL servers via
a crafted certificate issued by a legitimate Certification Authority.
(CVE-2009-2730 )

In addition, with this update, certificates with MD2 hash signatures
are no longer accepted since they're no longer considered
cryptograhically secure. It only affects the oldstable distribution
(etch).(CVE-2009-2409 )"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=541439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2730"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2409"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1935"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gnutls13/gnutls26 packages.

For the oldstable distribution (etch), these problems have been fixed
in version 1.4.4-3+etch5 for gnutls13.

For the stable distribution (lenny), these problems have been fixed in
version 2.4.2-6+lenny2 for gnutls26."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnutls13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnutls26");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"gnutls-bin", reference:"1.4.4-3+etch5")) flag++;
if (deb_check(release:"4.0", prefix:"gnutls-doc", reference:"1.4.4-3+etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libgnutls-dev", reference:"1.4.4-3+etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libgnutls13", reference:"1.4.4-3+etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libgnutls13-dbg", reference:"1.4.4-3+etch5")) flag++;
if (deb_check(release:"5.0", prefix:"gnutls-bin", reference:"2.4.2-6+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"gnutls-doc", reference:"2.4.2-6+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"guile-gnutls", reference:"2.4.2-6+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libgnutls-dev", reference:"2.4.2-6+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libgnutls26", reference:"2.4.2-6+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libgnutls26-dbg", reference:"2.4.2-6+lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
