#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1087. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22629);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/05/03 11:14:57 $");

  script_cve_id("CVE-2006-2313", "CVE-2006-2314");
  script_osvdb_id(25730, 25731);
  script_xref(name:"DSA", value:"1087");

  script_name(english:"Debian DSA-1087-1 : postgresql - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several encoding problems have been discovered in PostgreSQL, a
popular SQL database. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2006-2313
    Akio Ishida and Yasuo Ohgaki discovered a weakness in
    the handling of invalidly-encoded multibyte text data
    which could allow an attacker to inject arbitrary SQL
    commands.

  - CVE-2006-2314
    A similar problem exists in client-side encodings (such
    as SJIS, BIG5, GBK, GB18030, and UHC) which contain
    valid multibyte characters that end with the backslash
    character. An attacker could supply a specially crafted
    byte sequence that is able to inject arbitrary SQL
    commands.

  This issue does not affect you if you only use single-byte (like
  SQL_ASCII or the ISO-8859-X family) or unaffected multibyte (like
  UTF-8) encodings.

  psycopg and python-pgsql use the old encoding for binary data and
  may have to be updated.

The old stable distribution (woody) is affected by these problems but
we're unable to correct the package."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1087"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the postgresql packages.

For the stable distribution (sarge) these problems have been fixed in
version 7.4.7-6sarge2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libecpg-dev", reference:"7.4.7-6sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libecpg4", reference:"7.4.7-6sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libpgtcl", reference:"7.4.7-6sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libpgtcl-dev", reference:"7.4.7-6sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libpq3", reference:"7.4.7-6sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"postgresql", reference:"7.4.7-6sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"postgresql-client", reference:"7.4.7-6sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"postgresql-contrib", reference:"7.4.7-6sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"postgresql-dev", reference:"7.4.7-6sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"postgresql-doc", reference:"7.4.7-6sarge2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
