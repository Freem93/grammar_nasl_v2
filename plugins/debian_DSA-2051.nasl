#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2051. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46710);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2010-0442", "CVE-2010-1168", "CVE-2010-1169", "CVE-2010-1170", "CVE-2010-1975");
  script_bugtraq_id(37973, 40215, 40304);
  script_osvdb_id(62129, 64755, 64757, 64792);
  script_xref(name:"DSA", value:"2051");

  script_name(english:"Debian DSA-2051-1 : postgresql-8.3 - several vulnerabilities");
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

  - CVE-2010-1169
    Tim Bunce discovered that the implementation of the
    procedural language PL/Perl insufficiently restricts the
    subset of allowed code, which allows authenticated users
    the execution of arbitrary Perl code.

  - CVE-2010-1170
    Tom Lane discovered that the implementation of the
    procedural language PL/Tcl insufficiently restricts the
    subset of allowed code, which allows authenticated users
    the execution of arbitrary Tcl code.

  - CVE-2010-1975
    It was discovered that an unprivileged user could reset
    superuser-only parameter settings."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0442"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2051"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the postgresql-8.3 packages.

For the stable distribution (lenny), these problems have been fixed in
version 8.3.11-0lenny1. This update also introduces a fix for
CVE-2010-0442, which was originally scheduled for the next Lenny point
update."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-8.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"libecpg-compat3", reference:"8.3.11-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libecpg-dev", reference:"8.3.11-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libecpg6", reference:"8.3.11-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libpgtypes3", reference:"8.3.11-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libpq-dev", reference:"8.3.11-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libpq5", reference:"8.3.11-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql", reference:"8.3.11-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-8.3", reference:"8.3.11-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-client", reference:"8.3.11-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-client-8.3", reference:"8.3.11-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-contrib", reference:"8.3.11-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-contrib-8.3", reference:"8.3.11-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-doc", reference:"8.3.11-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-doc-8.3", reference:"8.3.11-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-plperl-8.3", reference:"8.3.11-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-plpython-8.3", reference:"8.3.11-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-pltcl-8.3", reference:"8.3.11-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-server-dev-8.3", reference:"8.3.11-0lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
