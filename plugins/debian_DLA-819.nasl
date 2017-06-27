#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-819-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97087);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/02/13 20:45:09 $");

  script_name(english:"Debian DLA-819-2 : mysql-5.5 version number correction");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is a correction of DLA 819-1 that mentioned that mysql-5.5
5.5.47-0+deb7u2 was corrected. The corrected package version was
5.5.54-0+deb7u2.

For completeness the text from DLA 819-1 is available below with only
corrected version information. No other changes.

It has been found that the C client library for MySQL
(libmysqlclient.so) has use-after-free vulnerability which can cause
crash of applications using that MySQL client.

For Debian 7 'Wheezy', these problems have been fixed in version
5.5.54-0+deb7u2.

We recommend that you upgrade your mysql-5.5 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/02/msg00009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/mysql-5.5"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmysqlclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmysqlclient18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmysqld-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmysqld-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-client-5.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-server-5.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-server-core-5.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-source-5.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-testsuite-5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/10");
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
if (deb_check(release:"7.0", prefix:"libmysqlclient-dev", reference:"5.5.54-0+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libmysqlclient18", reference:"5.5.54-0+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libmysqld-dev", reference:"5.5.54-0+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libmysqld-pic", reference:"5.5.54-0+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-client", reference:"5.5.54-0+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-client-5.5", reference:"5.5.54-0+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-common", reference:"5.5.54-0+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-server", reference:"5.5.54-0+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-server-5.5", reference:"5.5.54-0+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-server-core-5.5", reference:"5.5.54-0+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-source-5.5", reference:"5.5.54-0+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-testsuite-5.5", reference:"5.5.54-0+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
