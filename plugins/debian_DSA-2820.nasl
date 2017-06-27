#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2820. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71502);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/05 14:58:43 $");

  script_cve_id("CVE-2013-5607");
  script_bugtraq_id(63802);
  script_osvdb_id(99748);
  script_xref(name:"DSA", value:"2820");

  script_name(english:"Debian DSA-2820-1 : nspr - integer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that NSPR, Netscape Portable Runtime library, could
crash an application using the library when parsing a certificate that
causes an integer overflow. This flaw only affects 64-bit systems."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/nspr"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/nspr"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2820"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the nspr packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 4.8.6-1+squeeze1.

For the stable distribution (wheezy), this problem has been fixed in
version 2:4.9.2-1+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nspr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libnspr4-0d", reference:"4.8.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libnspr4-0d-dbg", reference:"4.8.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libnspr4-dev", reference:"4.8.6-1+squeeze1")) flag++;
if (deb_check(release:"7.0", prefix:"libnspr4", reference:"2:4.9.2-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libnspr4-0d", reference:"2:4.9.2-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libnspr4-dbg", reference:"2:4.9.2-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libnspr4-dev", reference:"2:4.9.2-1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
