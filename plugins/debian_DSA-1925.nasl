#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1925. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44790);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/03/30 13:45:22 $");

  script_cve_id("CVE-2009-3639");
  script_bugtraq_id(36804);
  script_osvdb_id(59292);
  script_xref(name:"DSA", value:"1925");

  script_name(english:"Debian DSA-1925-1 : proftpd-dfsg - insufficient input validation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It has been discovered that proftpd-dfsg, a virtual-hosting FTP
daemon, does not properly handle a '\0' character in a domain name in
the Subject Alternative Name field of an X.509 client certificate,
when the dNSNameRequired TLS option is enabled."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1925"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the proftpd-dfsg packages.

For the stable distribution (lenny), this problem has been fixed in
version 1.3.1-17lenny4.

For the oldstable distribution (etch), this problem has been fixed in
version 1.3.0-19etch3.

Binaries for the amd64 architecture will be released once they are
available."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-dfsg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/31");
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
if (deb_check(release:"4.0", prefix:"proftpd", reference:"1.3.0-19etch3")) flag++;
if (deb_check(release:"4.0", prefix:"proftpd-doc", reference:"1.3.0-19etch3")) flag++;
if (deb_check(release:"4.0", prefix:"proftpd-ldap", reference:"1.3.0-19etch3")) flag++;
if (deb_check(release:"4.0", prefix:"proftpd-mysql", reference:"1.3.0-19etch3")) flag++;
if (deb_check(release:"4.0", prefix:"proftpd-pgsql", reference:"1.3.0-19etch3")) flag++;
if (deb_check(release:"5.0", prefix:"proftpd", reference:"1.3.1-17lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"proftpd-basic", reference:"1.3.1-17lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"proftpd-doc", reference:"1.3.1-17lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"proftpd-mod-ldap", reference:"1.3.1-17lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"proftpd-mod-mysql", reference:"1.3.1-17lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"proftpd-mod-pgsql", reference:"1.3.1-17lenny4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
