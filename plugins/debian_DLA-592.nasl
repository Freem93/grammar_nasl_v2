#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-592-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92873);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/08/12 13:55:49 $");

  script_name(english:"Debian DLA-592-1 : postgresql-9.1 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been found in PostgreSQL, a SQL database
system.

CVE-2016-5423

Karthikeyan Jambu Rajaraman discovered that nested CASE-WHEN
expressions are not properly evaluated, potentially leading to a crash
or allowing to disclose portions of server memory.

CVE-2016-5424

Nathan Bossart discovered that special characters in database and role
names are not properly handled, potentially leading to the execution
of commands with superuser privileges, when a superuser executes
pg_dumpall or other routine maintenance operations.

For Debian 7 'Wheezy', these problems have been fixed in version
9.1.23-0+deb7u1.

We recommend that you upgrade your postgresql-9.1 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/08/msg00017.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/postgresql-9.1"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/12");
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
if (deb_check(release:"7.0", prefix:"libecpg-compat3", reference:"9.1.23-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libecpg-dev", reference:"9.1.23-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libecpg6", reference:"9.1.23-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpgtypes3", reference:"9.1.23-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpq-dev", reference:"9.1.23-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpq5", reference:"9.1.23-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-9.1", reference:"9.1.23-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-9.1-dbg", reference:"9.1.23-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-client-9.1", reference:"9.1.23-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-contrib-9.1", reference:"9.1.23-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-doc-9.1", reference:"9.1.23-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-plperl-9.1", reference:"9.1.23-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-plpython-9.1", reference:"9.1.23-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-plpython3-9.1", reference:"9.1.23-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-pltcl-9.1", reference:"9.1.23-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-server-dev-9.1", reference:"9.1.23-0+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
