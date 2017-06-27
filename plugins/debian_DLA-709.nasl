#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-709-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94917);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/11/16 21:58:17 $");

  script_name(english:"Debian DLA-709-1 : postgresql-9.1 update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several bugs were discovered in PostgreSQL, a relational database
server system. This update corrects various stability issues.

9.1.24 marks the end of life of the PostgreSQL 9.1 branch.
No further releases will be made by the PostgreSQL Global
Development Group.

Users of PostgreSQL 9.1 should look into upgrading to a
newer PostgreSQL release. Options are :

  - Upgrading to Debian 8 (Jessie), providing
    postgresql-9.4.

  - The use of the apt.postgresql.org repository, providing
    packages for all active PostgreSQL branches (9.2 up to
    9.6 at the time of writing).

    See https://wiki.postgresql.org/wiki/Apt for more
    information about the repository.

    A helper script to activate the repository is provided
    in
    /usr/share/doc/postgresql-9.1/examples/apt.postgresql.or
    g.sh.gz.

  - In Debian, an LTS version of 9.1 is in planning that
    will cover the lifetime of wheezy-lts. Updates will made
    on a best-effort basis. Users can take advantage of
    this, but should still consider upgrading to newer
    PostgreSQL versions over the next months.

    See https://wiki.debian.org/LTS for more information
    about Debian LTS.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/11/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/postgresql-9.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.debian.org/LTS"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.postgresql.org/wiki/Apt"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-9.1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-client-9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-contrib-9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-doc-9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-plperl-9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-plpython-9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-plpython3-9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-pltcl-9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-server-dev-9.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libecpg-compat3", reference:"9.1.24-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libecpg-dev", reference:"9.1.24-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libecpg6", reference:"9.1.24-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpgtypes3", reference:"9.1.24-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpq-dev", reference:"9.1.24-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpq5", reference:"9.1.24-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-9.1", reference:"9.1.24-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-9.1-dbg", reference:"9.1.24-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-client-9.1", reference:"9.1.24-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-contrib-9.1", reference:"9.1.24-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-doc-9.1", reference:"9.1.24-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-plperl-9.1", reference:"9.1.24-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-plpython-9.1", reference:"9.1.24-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-plpython3-9.1", reference:"9.1.24-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-pltcl-9.1", reference:"9.1.24-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-server-dev-9.1", reference:"9.1.24-0+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
