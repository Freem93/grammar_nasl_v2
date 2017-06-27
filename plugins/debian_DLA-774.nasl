#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-774-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96190);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/01/04 15:51:46 $");

  script_name(english:"Debian DLA-774-1 : postgresql-common security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A security vulnerability and a data loss bug have been found in
postgresql-common, Debian's PostgreSQL database cluster management
tools.

CVE-2016-1255

Dawid Golunski discovered that a symlink in /var/log/postgresql/ could
be used by the 'postgres' system user to write to arbitrary files on
the filesystem the next time PostgreSQL is started by root.

#614374

Rafa&#x142; Kupka discovered that pg_upgradecluster did not properly
upgrade databases that are owned by a non-login role (or group).

For Debian 7 'Wheezy', these problems have been fixed in version
134wheezy5.

We recommend that you upgrade your postgresql-common packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/01/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/postgresql-common"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-server-dev-all");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"postgresql", reference:"9.1+134wheezy5")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-client", reference:"9.1+134wheezy5")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-client-common", reference:"9.1+134wheezy5")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-common", reference:"9.1+134wheezy5")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-contrib", reference:"9.1+134wheezy5")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-doc", reference:"9.1+134wheezy5")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-server-dev-all", reference:"9.1+134wheezy5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
