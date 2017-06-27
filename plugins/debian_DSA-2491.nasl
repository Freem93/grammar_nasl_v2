#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2491. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59769);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/02/16 15:37:38 $");

  script_cve_id("CVE-2012-2143", "CVE-2012-2655");
  script_bugtraq_id(53729, 53812);
  script_osvdb_id(82578, 82630);
  script_xref(name:"DSA", value:"2491");

  script_name(english:"Debian DSA-2491-1 : postgresql-8.4 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were discovered in PostgreSQL, a SQL database
server :

  - CVE-2012-2143
    The crypt(text, text) function in the pgcrypto contrib
    module did not handle certain passwords correctly when
    producing traditional DES-based hashes. Characters after
    the first 0x80 byte were ignored.

  - CVE-2012-2655
    SECURITY DEFINER and SET attributes for a call handler
    of a procedural language could crash the database
    server.

In addition, this update contains reliability and stability fixes from
the 8.4.12 upstream release."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-2143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-2655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/postgresql-8.4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2491"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the postgresql-8.4 packages.

For the stable distribution (squeeze), this problem has been fixed in
version 8.4.12-0squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libecpg-compat3", reference:"8.4.12-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libecpg-dev", reference:"8.4.12-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libecpg6", reference:"8.4.12-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libpgtypes3", reference:"8.4.12-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libpq-dev", reference:"8.4.12-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libpq5", reference:"8.4.12-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql", reference:"8.4.12-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-8.4", reference:"8.4.12-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-client", reference:"8.4.12-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-client-8.4", reference:"8.4.12-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-contrib", reference:"8.4.12-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-contrib-8.4", reference:"8.4.12-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-doc", reference:"8.4.12-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-doc-8.4", reference:"8.4.12-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-plperl-8.4", reference:"8.4.12-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-plpython-8.4", reference:"8.4.12-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-pltcl-8.4", reference:"8.4.12-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-server-dev-8.4", reference:"8.4.12-0squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
