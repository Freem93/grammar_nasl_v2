#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-165. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15002);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/17 23:49:55 $");

  script_cve_id("CVE-2002-0972", "CVE-2002-1397", "CVE-2002-1398", "CVE-2002-1400", "CVE-2002-1401", "CVE-2002-1402");
  script_osvdb_id(6190, 8998);
  script_xref(name:"DSA", value:"165");

  script_name(english:"Debian DSA-165-1 : postgresql - buffer overflows");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mordred Labs and others found several vulnerabilities in PostgreSQL,
an object-relational SQL database. They are inherited from several
buffer overflows and integer overflows. Specially crafted long date
and time input, currency, repeat data and long timezone names could
cause the PostgreSQL server to crash as well as specially crafted
input data for lpad() and rpad(). More buffer/integer overflows were
found in circle_poly(), path_encode() and path_addr().

Except for the last three, these problems are fixed in the upstream
release 7.2.2 of PostgreSQL which is the recommended version to use.

Most of these problems do not exist in the version of PostgreSQL that
Debian ships in the potato release since the corresponding
functionality is not yet implemented. However, PostgreSQL 6.5.3 is
quite old and may bear more risks than we are aware of, which may
include further buffer overflows, and certainly include bugs that
threaten the integrity of your data.

You are strongly advised not to use this release but to upgrade your
system to Debian 3.0 (stable) including PostgreSQL release 7.2.1
instead, where many bugs have been fixed and new features introduced
to increase compatibility with the SQL standards.

If you consider an upgrade, please make sure to dump the entire
database system using the pg_dumpall utility. Please take into
consideration that the newer PostgreSQL is more strict in its input
handling. This means that tests like 'foo = NULL' which are not valid
won't be accepted anymore. It also means that when using UNICODE
encoding, ISO 8859-1 and ISO 8859-15 are no longer valid encodings to
use when inserting data into the relation. In such a case you are
advised to convert the dump in question usingrecode latin1..utf-16.

These problems have been fixed in version 7.2.1-2woody2 for the
current stable distribution (woody) and in version 7.2.2-2 for the
unstable distribution (sid). The old stable distribution (potato) is
partially affected and we ship a fixed version 6.5.3-27.2 for it."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-165"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the PostgreSQL packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/08/19");
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
if (deb_check(release:"2.2", prefix:"ecpg", reference:"6.5.3-27.2")) flag++;
if (deb_check(release:"2.2", prefix:"libpgperl", reference:"6.5.3-27.2")) flag++;
if (deb_check(release:"2.2", prefix:"libpgsql2", reference:"6.5.3-27.2")) flag++;
if (deb_check(release:"2.2", prefix:"libpgtcl", reference:"6.5.3-27.2")) flag++;
if (deb_check(release:"2.2", prefix:"odbc-postgresql", reference:"6.5.3-27.2")) flag++;
if (deb_check(release:"2.2", prefix:"pgaccess", reference:"6.5.3-27.2")) flag++;
if (deb_check(release:"2.2", prefix:"postgresql", reference:"6.5.3-27.2")) flag++;
if (deb_check(release:"2.2", prefix:"postgresql-client", reference:"6.5.3-27.2")) flag++;
if (deb_check(release:"2.2", prefix:"postgresql-contrib", reference:"6.5.3-27.2")) flag++;
if (deb_check(release:"2.2", prefix:"postgresql-dev", reference:"6.5.3-27.2")) flag++;
if (deb_check(release:"2.2", prefix:"postgresql-doc", reference:"6.5.3-27.2")) flag++;
if (deb_check(release:"2.2", prefix:"postgresql-pl", reference:"6.5.3-27.2")) flag++;
if (deb_check(release:"2.2", prefix:"postgresql-test", reference:"6.5.3-27.2")) flag++;
if (deb_check(release:"2.2", prefix:"python-pygresql", reference:"6.5.3-27.2")) flag++;
if (deb_check(release:"3.0", prefix:"courier-authpostgresql", reference:"0.37.3-3.1")) flag++;
if (deb_check(release:"3.0", prefix:"libecpg3", reference:"7.2.1-2woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libpgperl", reference:"7.2.1-2woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libpgsql2", reference:"7.2.1-2woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libpgtcl", reference:"7.2.1-2woody2")) flag++;
if (deb_check(release:"3.0", prefix:"odbc-postgresql", reference:"7.2.1-2woody2")) flag++;
if (deb_check(release:"3.0", prefix:"pgaccess", reference:"7.2.1-2woody2")) flag++;
if (deb_check(release:"3.0", prefix:"postgresql", reference:"7.2.1-2woody2")) flag++;
if (deb_check(release:"3.0", prefix:"postgresql-client", reference:"7.2.1-2woody2")) flag++;
if (deb_check(release:"3.0", prefix:"postgresql-contrib", reference:"7.2.1-2woody2")) flag++;
if (deb_check(release:"3.0", prefix:"postgresql-dev", reference:"7.2.1-2woody2")) flag++;
if (deb_check(release:"3.0", prefix:"postgresql-doc", reference:"7.2.1-2woody2")) flag++;
if (deb_check(release:"3.0", prefix:"python-pygresql", reference:"7.2.1-2woody2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
