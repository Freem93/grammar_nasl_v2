#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-068. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14905);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/17 23:36:50 $");

  script_cve_id("CVE-2001-0977");
  script_bugtraq_id(3049);
  script_xref(name:"DSA", value:"068");

  script_name(english:"Debian DSA-068-1 : openldap - remote DoS");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The CERT advisory lists a number of vulnerabilities in various LDAP
 implementations, based on the results of the PROTOS LDAPv3 test
 suite. These tests found one problem in OpenLDAP, a free LDAP
 implementation which is shipped as part of Debian GNU/Linux 2.2.

The problem is that slapd did not handle packets which had BER fields
of invalid length and would crash if it received them. An attacker
could use this to mount a remote denial of service attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2001/dsa-068"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"This problem has been fixed in version 1.2.12-1, and we recommend that
you upgrade your slapd package immediately."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openldap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/08/09");
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
if (deb_check(release:"2.2", prefix:"ldap-rfc", reference:"1.2.12-1")) flag++;
if (deb_check(release:"2.2", prefix:"libopenldap-dev", reference:"1.2.12-1")) flag++;
if (deb_check(release:"2.2", prefix:"libopenldap-runtime", reference:"1.2.12-1")) flag++;
if (deb_check(release:"2.2", prefix:"libopenldap1", reference:"1.2.12-1")) flag++;
if (deb_check(release:"2.2", prefix:"openldap-gateways", reference:"1.2.12-1")) flag++;
if (deb_check(release:"2.2", prefix:"openldap-utils", reference:"1.2.12-1")) flag++;
if (deb_check(release:"2.2", prefix:"openldapd", reference:"1.2.12-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
