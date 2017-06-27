#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3417. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87359);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2015-7940");
  script_osvdb_id(129389);
  script_xref(name:"DSA", value:"3417");

  script_name(english:"Debian DSA-3417-1 : bouncycastle - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tibor Jager, Jorg Schwenk, and Juraj Somorovsky, from Horst Gortz
Institute for IT Security, published a paper in ESORICS 2015 where
they describe an invalid curve attack in Bouncy Castle Crypto, a Java
library for cryptography. An attacker is able to recover private
Elliptic Curve keys from different applications, for example, TLS
servers.

More information:
http://web-in-security.blogspot.ca/2015/09/practical-invalid-curve-att
acks.htmlPractical Invalid Curve Attacks on TLS-ECDH:
http://euklid.org/pdf/ECC_Invalid_Curve.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=802671"
  );
  # http://web-in-security.blogspot.ca/2015/09/practical-invalid-curve-attacks.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?577fd981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://euklid.org/pdf/ECC_Invalid_Curve.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/bouncycastle"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/bouncycastle"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3417"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bouncycastle packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 1.44+dfsg-3.1+deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 1.49+dfsg-3+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bouncycastle");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libbcmail-java", reference:"1.44+dfsg-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libbcmail-java-doc", reference:"1.44+dfsg-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libbcmail-java-gcj", reference:"1.44+dfsg-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libbcpg-java", reference:"1.44+dfsg-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libbcpg-java-doc", reference:"1.44+dfsg-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libbcpg-java-gcj", reference:"1.44+dfsg-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libbcprov-java", reference:"1.44+dfsg-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libbcprov-java-doc", reference:"1.44+dfsg-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libbcprov-java-gcj", reference:"1.44+dfsg-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libbctsp-java", reference:"1.44+dfsg-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libbctsp-java-doc", reference:"1.44+dfsg-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libbctsp-java-gcj", reference:"1.44+dfsg-3.1+deb7u1")) flag++;
if (deb_check(release:"8.0", prefix:"libbcmail-java", reference:"1.49+dfsg-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libbcmail-java-doc", reference:"1.49+dfsg-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libbcpg-java", reference:"1.49+dfsg-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libbcpg-java-doc", reference:"1.49+dfsg-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libbcpkix-java", reference:"1.49+dfsg-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libbcpkix-java-doc", reference:"1.49+dfsg-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libbcprov-java", reference:"1.49+dfsg-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libbcprov-java-doc", reference:"1.49+dfsg-3+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
