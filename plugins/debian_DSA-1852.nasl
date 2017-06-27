#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1852. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44717);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/05/17 23:54:22 $");

  script_cve_id("CVE-2009-2666");
  script_osvdb_id(56855);
  script_xref(name:"DSA", value:"1852");

  script_name(english:"Debian DSA-1852-1 : fetchmail - insufficient input validation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that fetchmail, a full-featured remote mail
retrieval and forwarding utility, is vulnerable to the 'Null Prefix
Attacks Against SSL/TLS Certificates' recently published at the
Blackhat conference. This allows an attacker to perform undetected
man-in-the-middle attacks via a crafted ITU-T X.509 certificate with
an injected null byte in the subjectAltName or Common Name fields.

Note, as a fetchmail user you should always use strict certificate
validation through either these option combinations: sslcertck ssl
sslproto ssl3 (for service on SSL-wrapped ports) or sslcertck sslproto
tls1 (for STARTTLS-based services)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1852"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the fetchmail packages.

For the oldstable distribution (etch), this problem has been fixed in
version 6.3.6-1etch2.

For the stable distribution (lenny), this problem has been fixed in
version 6.3.9~rc2-4+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fetchmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/07");
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
if (deb_check(release:"4.0", prefix:"fetchmail", reference:"6.3.6-1etch2")) flag++;
if (deb_check(release:"4.0", prefix:"fetchmailconf", reference:"6.3.6-1etch2")) flag++;
if (deb_check(release:"5.0", prefix:"fetchmail", reference:"6.3.9~rc2-4+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"fetchmailconf", reference:"6.3.9~rc2-4+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
