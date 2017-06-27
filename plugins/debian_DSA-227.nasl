#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-227. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15064);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2013/05/17 23:58:37 $");

  script_cve_id("CVE-2002-1378", "CVE-2002-1379", "CVE-2002-1508");
  script_bugtraq_id(6328, 6620);
  script_osvdb_id(4798);
  script_xref(name:"DSA", value:"227");

  script_name(english:"Debian DSA-227-1 : openldap2 - buffer overflows and other bugs");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SuSE Security Team reviewed critical parts of openldap2, an
implementation of the Lightweight Directory Access Protocol (LDAP)
version 2 and 3, and found several buffer overflows and other bugs
remote attackers could exploit to gain access on systems running
vulnerable LDAP servers. In addition to these bugs, various local
exploitable bugs within the OpenLDAP2 libraries have been fixed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-227"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openldap2 packages.

For the current stable distribution (woody) these problems have been
fixed in version 2.0.23-6.3.

The old stable distribution (potato) does not contain OpenLDAP2
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openldap2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/12/06");
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
if (deb_check(release:"3.0", prefix:"ldap-gateways", reference:"2.0.23-6.3")) flag++;
if (deb_check(release:"3.0", prefix:"ldap-utils", reference:"2.0.23-6.3")) flag++;
if (deb_check(release:"3.0", prefix:"libldap2", reference:"2.0.23-6.3")) flag++;
if (deb_check(release:"3.0", prefix:"libldap2-dev", reference:"2.0.23-6.3")) flag++;
if (deb_check(release:"3.0", prefix:"slapd", reference:"2.0.23-6.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
