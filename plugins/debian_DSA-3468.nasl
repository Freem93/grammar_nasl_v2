#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3468. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88602);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/02/08 15:46:25 $");

  script_cve_id("CVE-2015-5291", "CVE-2015-8036");
  script_xref(name:"DSA", value:"3468");

  script_name(english:"Debian DSA-3468-1 : polarssl - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that polarssl, a library providing SSL and TLS
support, contained two heap-based buffer overflows that could allow a
remote attacker to trigger denial of service (via application crash)
or arbitrary code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=801413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/polarssl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/polarssl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3468"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the polarssl packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 1.2.9-1~deb7u6.

For the stable distribution (jessie), these problems have been fixed
in version 1.3.9-2.1+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:polarssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libpolarssl-dev", reference:"1.2.9-1~deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libpolarssl-runtime", reference:"1.2.9-1~deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libpolarssl0", reference:"1.2.9-1~deb7u6")) flag++;
if (deb_check(release:"8.0", prefix:"libpolarssl-dev", reference:"1.3.9-2.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpolarssl-runtime", reference:"1.3.9-2.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpolarssl7", reference:"1.3.9-2.1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
