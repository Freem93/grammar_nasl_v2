#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2340. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56730);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2011-2483");
  script_bugtraq_id(49241);
  script_osvdb_id(74742);
  script_xref(name:"DSA", value:"2340");

  script_name(english:"Debian DSA-2340-1 : postgresql-8.3, postgresql-8.4, postgresql-9.0 - weak password hashing");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"magnum discovered that the blowfish password hashing used amongst
others in PostgreSQL contained a weakness that would give passwords
with 8 bit characters the same hash as weaker equivalents."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=631285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/postgresql-8.4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2340"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the postgresql packages.

For the oldstable distribution (lenny), this problem has been fixed in
postgresql-8.3 version 8.3.16-0lenny1.

For the stable distribution (squeeze), this problem has been fixed in
postgresql-8.4 version 8.4.9-0squeeze1.

The updates also include reliability improvements, originally
scheduled for inclusion into the next point release; for details see
the respective changelogs."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-8.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-8.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"postgresql-8.3", reference:"8.3.16-0lenny1")) flag++;
if (deb_check(release:"6.0", prefix:"libecpg-compat3", reference:"8.4.9-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libecpg-dev", reference:"8.4.9-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libecpg6", reference:"8.4.9-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libpgtypes3", reference:"8.4.9-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libpq-dev", reference:"8.4.9-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libpq5", reference:"8.4.9-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql", reference:"8.4.9-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-8.4", reference:"8.4.9-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-client", reference:"8.4.9-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-client-8.4", reference:"8.4.9-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-contrib", reference:"8.4.9-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-contrib-8.4", reference:"8.4.9-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-doc", reference:"8.4.9-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-doc-8.4", reference:"8.4.9-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-plperl-8.4", reference:"8.4.9-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-plpython-8.4", reference:"8.4.9-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-pltcl-8.4", reference:"8.4.9-0squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-server-dev-8.4", reference:"8.4.9-0squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
