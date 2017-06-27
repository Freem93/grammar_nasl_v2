#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1042. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22584);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/17 23:36:51 $");

  script_cve_id("CVE-2006-1721");
  script_bugtraq_id(17446);
  script_osvdb_id(24510);
  script_xref(name:"DSA", value:"1042");

  script_name(english:"Debian DSA-1042-1 : cyrus-sasl2 - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Mu Security research team discovered a denial of service condition
in the Simple Authentication and Security Layer authentication library
(SASL) during DIGEST-MD5 negotiation. This potentially affects
multiple products that use SASL DIGEST-MD5 authentication including
OpenLDAP, Sendmail, Postfix, etc."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=361937"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1042"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the cyrus-sasl2 packages.

The old stable distribution (woody) is not affected by this problem.

For the stable distribution (sarge) this problem has been fixed in
version 2.1.19-1.5sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-sasl2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/07");
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
if (deb_check(release:"3.1", prefix:"libsasl2", reference:"2.1.19-1.5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libsasl2-dev", reference:"2.1.19-1.5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libsasl2-modules", reference:"2.1.19-1.5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libsasl2-modules-gssapi-heimdal", reference:"2.1.19-1.5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libsasl2-modules-kerberos-heimdal", reference:"2.1.19-1.5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libsasl2-modules-sql", reference:"2.1.19-1.5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"sasl2-bin", reference:"2.1.19-1.5sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
