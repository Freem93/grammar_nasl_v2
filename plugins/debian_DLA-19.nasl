#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-19-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82167);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/12/02 20:08:16 $");

  script_cve_id("CVE-2014-0067");
  script_bugtraq_id(65721);
  script_osvdb_id(103550);

  script_name(english:"Debian DLA-19-1 : postgresql-8.4 update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New upstream minor release. Users should upgrade to this version at
their next scheduled maintenance window.

Noteworthy change :

Secure Unix-domain sockets of temporary postmasters started during
make check (Noah Misch)

Any local user able to access the socket file could connect
as the server's bootstrap superuser, then proceed to execute
arbitrary code as the operating-system user running the
test, as we previously noted in CVE-2014-0067. This change
defends against that risk by placing the server's socket in
a temporary, mode 0700 subdirectory of /tmp.

8.4.22 marks the end of life of the PostgreSQL 8.4 branch. No further
releases will be made by the PostgreSQL Global Development Group.

Users of PostgreSQL 8.4 should look into upgrading to a newer
PostgreSQL release. Options are :

  - Upgrading to Debian 7 (Wheezy), providing
    postgresql-9.1.

  - The use of the apt.postgresql.org repository, providing
    packages for all active PostgreSQL branches (9.0 up to
    9.4 at the time of writing).

    See https://wiki.postgresql.org/wiki/Apt for more
    information about the repository.

    A helper script to activate the repository is provided
    in
    /usr/share/doc/postgresql-8.4/examples/apt.postgresql.or
    g.sh.

  - An LTS version of 8.4 is in planning that will cover the
    lifetime of squeeze-lts. Updates will probably made on a
    best-effort basis. Users can take advantage of this, but
    should still consider upgrading to newer PostgreSQL
    versions over the next months.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2014/07/msg00008.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/postgresql-8.4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.postgresql.org/wiki/Apt"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
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
if (deb_check(release:"6.0", prefix:"libecpg-compat3", reference:"8.4.22-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libecpg-dev", reference:"8.4.22-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libecpg6", reference:"8.4.22-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libpgtypes3", reference:"8.4.22-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libpq-dev", reference:"8.4.22-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libpq5", reference:"8.4.22-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql", reference:"8.4.22-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-8.4", reference:"8.4.22-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-client", reference:"8.4.22-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-client-8.4", reference:"8.4.22-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-contrib", reference:"8.4.22-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-contrib-8.4", reference:"8.4.22-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-doc", reference:"8.4.22-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-doc-8.4", reference:"8.4.22-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-plperl-8.4", reference:"8.4.22-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-plpython-8.4", reference:"8.4.22-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-pltcl-8.4", reference:"8.4.22-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-server-dev-8.4", reference:"8.4.22-0+deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
