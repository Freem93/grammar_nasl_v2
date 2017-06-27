#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-329-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86446);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/12/02 20:08:18 $");

  script_name(english:"Debian DLA-329-1 : postgresql-8.4 update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several bugs were discovered in PostgreSQL, a relational database
server system. The 8.4 branch is EOLed upstream, but still present in
Debian squeeze. This new LTS minor version contains the fixes that
were applied upstream to the 9.0.22 version, backported to 8.4.22
which was the last version officially released by the PostgreSQL
developers. This LTS effort for squeeze-lts is a community project
sponsored by credativ GmbH.

## Migration to Version 8.4.22lts5

A dump/restore is not required for those running 8.4.X. However, if
you are upgrading from a version earlier than 8.4.22, see the relevant
release notes.

## Security Fixes

Fix contrib/pgcrypto to detect and report too-short crypt salts (Josh
Kupershmidt)

Certain invalid salt arguments crashed the server or disclosed a few
bytes of server memory. We have not ruled out the viability of attacks
that arrange for presence of confidential information in the disclosed
bytes, but they seem unlikely. (CVE-2015-5288)

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/10/msg00007.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/postgresql-8.4"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libecpg-compat3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libecpg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpgtypes3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpq-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-8.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-client-8.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-contrib-8.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-doc-8.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-plperl-8.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-plpython-8.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-pltcl-8.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-server-dev-8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libecpg-compat3", reference:"8.4.22lts5-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libecpg-dev", reference:"8.4.22lts5-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libecpg6", reference:"8.4.22lts5-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libpgtypes3", reference:"8.4.22lts5-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libpq-dev", reference:"8.4.22lts5-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libpq5", reference:"8.4.22lts5-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql", reference:"8.4.22lts5-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-8.4", reference:"8.4.22lts5-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-client", reference:"8.4.22lts5-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-client-8.4", reference:"8.4.22lts5-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-contrib", reference:"8.4.22lts5-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-contrib-8.4", reference:"8.4.22lts5-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-doc", reference:"8.4.22lts5-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-doc-8.4", reference:"8.4.22lts5-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-plperl-8.4", reference:"8.4.22lts5-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-plpython-8.4", reference:"8.4.22lts5-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-pltcl-8.4", reference:"8.4.22lts5-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-server-dev-8.4", reference:"8.4.22lts5-0+deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
