#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2031. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45479);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2010-0629");
  script_bugtraq_id(39247);
  script_osvdb_id(63569);
  script_xref(name:"DSA", value:"2031");

  script_name(english:"Debian DSA-2031-1 : krb5 - use-after-free");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sol Jerome discovered that kadmind service in krb5, a system for
authenticating users and services on a network, allows remote
authenticated users to cause a denial of service (daemon crash) via a
request from a kadmin client that sends an invalid API version number."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=567052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2031"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the krb5 package.

For the stable distribution (lenny), this problem has been fixed in
version 1.6.dfsg.4~beta1-5lenny3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/12");
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
if (deb_check(release:"5.0", prefix:"krb5-admin-server", reference:"1.6.dfsg.4~beta1-5lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-clients", reference:"1.6.dfsg.4~beta1-5lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-doc", reference:"1.6.dfsg.4~beta1-5lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-ftpd", reference:"1.6.dfsg.4~beta1-5lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-kdc", reference:"1.6.dfsg.4~beta1-5lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-kdc-ldap", reference:"1.6.dfsg.4~beta1-5lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-pkinit", reference:"1.6.dfsg.4~beta1-5lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-rsh-server", reference:"1.6.dfsg.4~beta1-5lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-telnetd", reference:"1.6.dfsg.4~beta1-5lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"krb5-user", reference:"1.6.dfsg.4~beta1-5lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"libkadm55", reference:"1.6.dfsg.4~beta1-5lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"libkrb5-dbg", reference:"1.6.dfsg.4~beta1-5lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"libkrb5-dev", reference:"1.6.dfsg.4~beta1-5lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"libkrb53", reference:"1.6.dfsg.4~beta1-5lenny3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
