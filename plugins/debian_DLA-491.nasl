#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-491-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91358);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/05/31 17:32:21 $");

  script_name(english:"Debian DLA-491-1 : postgresql-9.1 bugfix update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The PostgreSQL project released a new version of the PostgreSQL 9.1
branch :

  - Clear the OpenSSL error queue before OpenSSL calls,
    rather than assuming it's clear already; and make sure
    we leave it clear afterwards (Peter Geoghegan, Dave
    Vitek, Peter Eisentraut)

This change prevents problems when there are multiple connections
using OpenSSL within a single process and not all the code involved
follows the same rules for when to clear the error queue. Failures
have been reported specifically when a client application uses SSL
connections in libpq concurrently with SSL connections using the PHP,
Python, or Ruby wrappers for OpenSSL. It's possible for similar
problems to arise within the server as well, if an extension module
establishes an outgoing SSL connection.

  - Fix 'failed to build any N-way joins' planner error with
    a full join enclosed in the right-hand side of a left
    join (Tom Lane)

  - Fix possible misbehavior of TH, th, and Y,YYY format
    codes in to_timestamp() (Tom Lane)

These could advance off the end of the input string, causing
subsequent format codes to read garbage.

  - Fix dumping of rules and views in which the array
    argument of a value operator ANY (array) construct is a
    sub-SELECT (Tom Lane)

  - Make pg_regress use a startup timeout from the
    PGCTLTIMEOUT environment variable, if that's set (Tom
    Lane)

This is for consistency with a behavior recently added to pg_ctl; it
eases automated testing on slow machines.

  - Fix pg_upgrade to correctly restore extension membership
    for operator families containing only one operator class
    (Tom Lane)

In such a case, the operator family was restored into the new
database, but it was no longer marked as part of the extension. This
had no immediate ill effects, but would cause later pg_dump runs to
emit output that would cause (harmless) errors on restore.

  - Rename internal function strtoi() to strtoint() to avoid
    conflict with a NetBSD library function (Thomas Munro)

  - Use the FORMAT_MESSAGE_IGNORE_INSERTS flag where
    appropriate. No live bug is known to exist here, but it
    seems like a good idea to be careful.

For Debian 7 'Wheezy', these problems have been fixed in version
9.1.22-0+deb7u1.

We recommend that you upgrade your postgresql-9.1 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/05/msg00044.html"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/31");
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
if (deb_check(release:"7.0", prefix:"libecpg-compat3", reference:"9.1.22-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libecpg-dev", reference:"9.1.22-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libecpg6", reference:"9.1.22-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpgtypes3", reference:"9.1.22-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpq-dev", reference:"9.1.22-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpq5", reference:"9.1.22-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-9.1", reference:"9.1.22-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-9.1-dbg", reference:"9.1.22-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-client-9.1", reference:"9.1.22-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-contrib-9.1", reference:"9.1.22-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-doc-9.1", reference:"9.1.22-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-plperl-9.1", reference:"9.1.22-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-plpython-9.1", reference:"9.1.22-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-plpython3-9.1", reference:"9.1.22-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-pltcl-9.1", reference:"9.1.22-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-server-dev-9.1", reference:"9.1.22-0+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
