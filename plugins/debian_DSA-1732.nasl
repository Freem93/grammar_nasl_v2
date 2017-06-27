#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1732. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35763);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/05/17 23:49:56 $");

  script_cve_id("CVE-2009-0478");
  script_xref(name:"DSA", value:"1732");

  script_name(english:"Debian DSA-1732-1 : squid3 - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Joshua Morin, Mikko Varpiola and Jukka Taimisto discovered an
assertion error in squid3, a full featured Web Proxy cache, which
could lead to a denial of service attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1732"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the oldstable distribution (etch), this problem has been fixed in
version 3.0.PRE5-5+etch1.

For the stable distribution (lenny), this problem has been fixed in
version 3.0.STABLE8-3, which was already included in the lenny
release."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"squid3", reference:"3.0.PRE5-5+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"squid3-cgi", reference:"3.0.PRE5-5+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"squid3-client", reference:"3.0.PRE5-5+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"squid3-common", reference:"3.0.PRE5-5+etch1")) flag++;
if (deb_check(release:"5.0", prefix:"squid3", reference:"3.0.STABLE8-3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
