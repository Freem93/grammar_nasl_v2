#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1463. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29968);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-3278", "CVE-2007-4769", "CVE-2007-4772", "CVE-2007-6067", "CVE-2007-6600", "CVE-2007-6601");
  script_osvdb_id(40899, 40902, 40903, 40904, 40905, 40906);
  script_xref(name:"DSA", value:"1463");

  script_name(english:"Debian DSA-1463-1 : postgresql-7.4 - several vulnerabilities");
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
    value:"https://security-tracker.debian.org/tracker/CVE-2007-6600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1463"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the postgresql-7.4 packages.

For the old stable distribution (sarge), some of these problems have
been fixed in version 7.4.7-6sarge6 of the postgresql package. Please
note that the fix for CVE-2007-6600 and for the handling of regular
expressions havn't been backported due to the intrusiveness of the
fix. We recommend to upgrade to the stable distribution if these
vulnerabilities affect your setup.

For the stable distribution (etch), these problems have been fixed in
version 7.4.19-0etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/15");
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
if (deb_check(release:"3.1", prefix:"libecpg-dev", reference:"7.4.7-6sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"libecpg4", reference:"7.4.7-6sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"libpgtcl", reference:"7.4.7-6sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"libpgtcl-dev", reference:"7.4.7-6sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"libpq3", reference:"7.4.7-6sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"postgresql", reference:"7.4.7-6sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"postgresql-client", reference:"7.4.7-6sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"postgresql-contrib", reference:"7.4.7-6sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"postgresql-dev", reference:"7.4.7-6sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"postgresql-doc", reference:"7.4.7-6sarge6")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-7.4", reference:"7.4.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-client-7.4", reference:"7.4.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-contrib-7.4", reference:"7.4.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-doc-7.4", reference:"7.4.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-plperl-7.4", reference:"7.4.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-plpython-7.4", reference:"7.4.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-pltcl-7.4", reference:"7.4.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-server-dev-7.4", reference:"7.4.19-0etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
