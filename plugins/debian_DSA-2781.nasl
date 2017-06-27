#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2781. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70503);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/16 15:43:10 $");

  script_cve_id("CVE-2013-1445");
  script_bugtraq_id(63201);
  script_xref(name:"DSA", value:"2781");

  script_name(english:"Debian DSA-2781-1 : python-crypto - PRNG not correctly reseeded in some situations");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A cryptographic vulnerability was discovered in the pseudo random
number generator in python-crypto.

In some situations, a race condition could prevent the reseeding of
the generator when multiple processes are forked from the same parent.
This would lead it to generate identical output on all processes,
which might leak sensitive values like cryptographic keys."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/python-crypto"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/python-crypto"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2781"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the python-crypto packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 2.1.0-2+squeeze2.

For the stable distribution (wheezy), this problem has been fixed in
version 2.6-4+deb7u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-crypto");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/20");
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
if (deb_check(release:"6.0", prefix:"python-crypto", reference:"2.1.0-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"python-crypto-dbg", reference:"2.1.0-2+squeeze2")) flag++;
if (deb_check(release:"7.0", prefix:"python-crypto", reference:"2.6-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"python-crypto-dbg", reference:"2.6-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"python-crypto-doc", reference:"2.6-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"python3-crypto", reference:"2.6-4+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"python3-crypto-dbg", reference:"2.6-4+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
