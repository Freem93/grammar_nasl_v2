#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2763. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70105);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:43:09 $");

  script_cve_id("CVE-2013-4314");
  script_bugtraq_id(62258);
  script_osvdb_id(97013);
  script_xref(name:"DSA", value:"2763");

  script_name(english:"Debian DSA-2763-1 : pyopenssl - hostname check bypassing");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that PyOpenSSL, a Python wrapper around the OpenSSL
library, does not properly handle certificates with NULL characters in
the Subject Alternative Name field.

A remote attacker in the position to obtain a certificate for
'www.foo.org\0.example.com' from a CA that a SSL client trusts, could
use this to spoof 'www.foo.org' and conduct man-in-the-middle attacks
between the PyOpenSSL-using client and the SSL server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=722055"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/pyopenssl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/pyopenssl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2763"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the pyopenssl packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 0.10-1+squeeze1.

For the stable distribution (wheezy), this problem has been fixed in
version 0.13-2+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pyopenssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"python-openssl", reference:"0.10-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"python-openssl-dbg", reference:"0.10-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"python-openssl-doc", reference:"0.10-1+squeeze1")) flag++;
if (deb_check(release:"7.0", prefix:"python-openssl", reference:"0.13-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python-openssl-dbg", reference:"0.13-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python-openssl-doc", reference:"0.13-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python3-openssl", reference:"0.13-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python3-openssl-dbg", reference:"0.13-2+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
