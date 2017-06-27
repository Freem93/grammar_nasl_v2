#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1460. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29937);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-3278", "CVE-2007-4769", "CVE-2007-4772", "CVE-2007-6067", "CVE-2007-6600", "CVE-2007-6601");
  script_osvdb_id(40899);
  script_xref(name:"DSA", value:"1460");

  script_name(english:"Debian DSA-1460-1 : postgresql-8.1 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several local vulnerabilities have been discovered in PostgreSQL, an
object-relational SQL database. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2007-3278
    It was discovered that the DBLink module performed
    insufficient credential validation. This issue is also
    tracked as CVE-2007-6601, since the initial upstream fix
    was incomplete.

  - CVE-2007-4769
    Tavis Ormandy and Will Drewry discovered that a bug in
    the handling of back-references inside the regular
    expressions engine could lead to an out of bounds read,
    resulting in a crash. This constitutes only a security
    problem if an application using PostgreSQL processes
    regular expressions from untrusted sources.

  - CVE-2007-4772
    Tavis Ormandy and Will Drewry discovered that the
    optimizer for regular expression could be tricked into
    an infinite loop, resulting in denial of service. This
    constitutes only a security problem if an application
    using PostgreSQL processes regular expressions from
    untrusted sources.

  - CVE-2007-6067
    Tavis Ormandy and Will Drewry discovered that the
    optimizer for regular expression could be tricked
    massive resource consumption. This constitutes only a
    security problem if an application using PostgreSQL
    processes regular expressions from untrusted sources.

  - CVE-2007-6600
    Functions in index expressions could lead to privilege
    escalation. For a more in depth explanation please see
    the upstream announce available at
    http://www.postgresql.org/about/news.905."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-6601"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-6067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-6600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/about/news.905"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1460"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the postgresql-8.1 (8.1.11-0etch1) package.

The old stable distribution (sarge), doesn't contain postgresql-8.1.

For the stable distribution (etch), these problems have been fixed in
version postgresql-8.1 8.1.11-0etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189, 264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libecpg-compat2", reference:"8.1.11-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libecpg-dev", reference:"8.1.11-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libecpg5", reference:"8.1.11-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libpgtypes2", reference:"8.1.11-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libpq-dev", reference:"8.1.11-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libpq4", reference:"8.1.11-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-8.1", reference:"8.1.11-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-client-8.1", reference:"8.1.11-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-contrib-8.1", reference:"8.1.11-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-doc-8.1", reference:"8.1.11-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-plperl-8.1", reference:"8.1.11-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-plpython-8.1", reference:"8.1.11-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-pltcl-8.1", reference:"8.1.11-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-server-dev-8.1", reference:"8.1.11-0etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
