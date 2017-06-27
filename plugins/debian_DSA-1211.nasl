#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1211. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23660);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/05/17 23:41:26 $");

  script_cve_id("CVE-2006-4251");
  script_osvdb_id(30334, 30335);
  script_xref(name:"DSA", value:"1211");

  script_name(english:"Debian DSA-1211-1 : pdns - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that malformed TCP packets may lead to denial of
service and possibly the execution of arbitrary code if the PowerDNS
nameserver acts as a recursive nameserver."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1211"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the PowerDNS packages.

For the stable distribution (sarge) this problem has been fixed in
version 2.9.17-13sarge3.

For the upcoming stable distribution (etch) this problem has been
fixed in version 3.1.4-1 of pdns-recursor."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/20");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"pdns", reference:"2.9.17-13sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"pdns-backend-geo", reference:"2.9.17-13sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"pdns-backend-ldap", reference:"2.9.17-13sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"pdns-backend-mysql", reference:"2.9.17-13sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"pdns-backend-pgsql", reference:"2.9.17-13sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"pdns-backend-pipe", reference:"2.9.17-13sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"pdns-backend-sqlite", reference:"2.9.17-13sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"pdns-doc", reference:"2.9.17-13sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"pdns-recursor", reference:"2.9.17-13sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"pdns-server", reference:"2.9.17-13sarge3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
