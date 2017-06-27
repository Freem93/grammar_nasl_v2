#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1182. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22724);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/05/17 23:41:26 $");

  script_cve_id("CVE-2006-4790");
  script_osvdb_id(28778);
  script_xref(name:"DSA", value:"1182");

  script_name(english:"Debian DSA-1182-1 : gnutls11 - cryptographic weakness");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Daniel Bleichenbacher discovered a flaw in GNU TLS cryptographic
package that could allow an attacker to generate a forged signature
that GNU TLS will accept as valid."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1182"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the GNU TLS package.

For the stable distribution (sarge) this problem has been fixed in
version 1.0.16-13.2sarge2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnutls11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/08");
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
if (deb_check(release:"3.1", prefix:"gnutls-bin", reference:"1.0.16-13.2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libgnutls11", reference:"1.0.16-13.2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libgnutls11-dbg", reference:"1.0.16-13.2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libgnutls11-dev", reference:"1.0.16-13.2sarge2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
