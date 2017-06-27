#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-247. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15084);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/18 00:02:54 $");

  script_cve_id("CVE-2003-0040");
  script_xref(name:"DSA", value:"247");

  script_name(english:"Debian DSA-247-1 : courier-ssl - missing input sanitizing");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The developers of courier, an integrated user side mail server,
discovered a problem in the PostgreSQL auth module. Not all
potentially malicious characters were sanitized before the username
was passed to the PostgreSQL engine. An attacker could inject
arbitrary SQL commands and queries exploiting this vulnerability. The
MySQL auth module is not affected."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-247"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the courier-authpostgresql package.

For the stable distribution (woody) this problem has been fixed in
version 0.37.3-3.3.

The old stable distribution (potato) does not contain courier
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:courier");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"courier-authpostgresql", reference:"0.37.3-3.3")) flag++;
if (deb_check(release:"3.0", prefix:"courier-imap-ssl", reference:"1.4.3-3.3")) flag++;
if (deb_check(release:"3.0", prefix:"courier-mta-ssl", reference:"0.37.3-3.3")) flag++;
if (deb_check(release:"3.0", prefix:"courier-pop-ssl", reference:"0.37.3-3.3")) flag++;
if (deb_check(release:"3.0", prefix:"courier-ssl", reference:"0.37.3-3.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
