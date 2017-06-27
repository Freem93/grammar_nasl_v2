#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-683. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16465);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/18 00:15:57 $");

  script_cve_id("CVE-2005-0245", "CVE-2005-0247");
  script_osvdb_id(13774, 13893, 13894, 13895, 13896);
  script_xref(name:"DSA", value:"683");

  script_name(english:"Debian DSA-683-1 : postgresql - buffer overflows");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several buffer overflows have been discovered in PL/PgSQL as part of
the PostgreSQL engine which could lead to the execution of arbitrary
code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-683"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the postgresql packages.

For the stable distribution (woody) these problems have been fixed in
version 7.2.1-2woody8."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/16");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"libecpg3", reference:"7.2.1-2woody8")) flag++;
if (deb_check(release:"3.0", prefix:"libpgperl", reference:"7.2.1-2woody8")) flag++;
if (deb_check(release:"3.0", prefix:"libpgsql2", reference:"7.2.1-2woody8")) flag++;
if (deb_check(release:"3.0", prefix:"libpgtcl", reference:"7.2.1-2woody8")) flag++;
if (deb_check(release:"3.0", prefix:"odbc-postgresql", reference:"7.2.1-2woody8")) flag++;
if (deb_check(release:"3.0", prefix:"pgaccess", reference:"7.2.1-2woody8")) flag++;
if (deb_check(release:"3.0", prefix:"postgresql", reference:"7.2.1-2woody8")) flag++;
if (deb_check(release:"3.0", prefix:"postgresql-client", reference:"7.2.1-2woody8")) flag++;
if (deb_check(release:"3.0", prefix:"postgresql-contrib", reference:"7.2.1-2woody8")) flag++;
if (deb_check(release:"3.0", prefix:"postgresql-dev", reference:"7.2.1-2woody8")) flag++;
if (deb_check(release:"3.0", prefix:"postgresql-doc", reference:"7.2.1-2woody8")) flag++;
if (deb_check(release:"3.0", prefix:"python-pygresql", reference:"7.2.1-2woody8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
