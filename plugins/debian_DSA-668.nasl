#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-668. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16342);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/18 00:15:57 $");

  script_cve_id("CVE-2005-0227");
  script_osvdb_id(13354);
  script_xref(name:"DSA", value:"668");

  script_name(english:"Debian DSA-668-1 : postgresql - privilege escalation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"John Heasman and others discovered a bug in the PostgreSQL engine
which would allow any user load an arbitrary local library into it."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=293125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-668"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the postgresql packages.

For the stable distribution (woody) this problem has been fixed in
version 7.2.1-2woody7."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/31");
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
if (deb_check(release:"3.0", prefix:"libecpg3", reference:"7.2.1-2woody7")) flag++;
if (deb_check(release:"3.0", prefix:"libpgperl", reference:"7.2.1-2woody7")) flag++;
if (deb_check(release:"3.0", prefix:"libpgsql2", reference:"7.2.1-2woody7")) flag++;
if (deb_check(release:"3.0", prefix:"libpgtcl", reference:"7.2.1-2woody7")) flag++;
if (deb_check(release:"3.0", prefix:"odbc-postgresql", reference:"7.2.1-2woody7")) flag++;
if (deb_check(release:"3.0", prefix:"pgaccess", reference:"7.2.1-2woody7")) flag++;
if (deb_check(release:"3.0", prefix:"postgresql", reference:"7.2.1-2woody7")) flag++;
if (deb_check(release:"3.0", prefix:"postgresql-client", reference:"7.2.1-2woody7")) flag++;
if (deb_check(release:"3.0", prefix:"postgresql-contrib", reference:"7.2.1-2woody7")) flag++;
if (deb_check(release:"3.0", prefix:"postgresql-dev", reference:"7.2.1-2woody7")) flag++;
if (deb_check(release:"3.0", prefix:"postgresql-doc", reference:"7.2.1-2woody7")) flag++;
if (deb_check(release:"3.0", prefix:"python-pygresql", reference:"7.2.1-2woody7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
