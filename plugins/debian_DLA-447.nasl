#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-447-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90804);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/06 20:03:51 $");

  script_cve_id("CVE-2016-0640", "CVE-2016-0641", "CVE-2016-0642", "CVE-2016-0643", "CVE-2016-0644", "CVE-2016-0646", "CVE-2016-0647", "CVE-2016-0648", "CVE-2016-0649", "CVE-2016-0650", "CVE-2016-0666", "CVE-2016-2047");
  script_osvdb_id(133627, 137324, 137325, 137326, 137328, 137336, 137337, 137339, 137341, 137342, 137343, 137349);

  script_name(english:"Debian DLA-447-1 : mysql-5.5 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovereded in the MySQL database
server, which are fixed in the new upstream version 5.5.49. Please see
the MySQL 5.5 Release Notes and Oracle's Critical Patch Update
advisory for further details :

https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-48.html
https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-49.html
http://www.oracle.com/technetwork/topics/security/cpuapr2016-2881694.h
tml

For Debian 7 'Wheezy', these issues have been fixed in mysql-5.5
version 5.5.49-0+deb7u1. We recommend you to upgrade your mysql-5.5
packages.

Learn more about the Debian Long Term Support (LTS) Project and how to
apply these updates at: https://wiki.debian.org/LTS/

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  # http://www.oracle.com/technetwork/topics/security/cpuapr2016-2881694.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f84b6b0a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-48.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-49.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/04/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/mysql-5.5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.debian.org/LTS/"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/02");
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
if (deb_check(release:"7.0", prefix:"libmysqlclient-dev", reference:"5.5.49-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmysqlclient18", reference:"5.5.49-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmysqld-dev", reference:"5.5.49-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmysqld-pic", reference:"5.5.49-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-client", reference:"5.5.49-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-client-5.5", reference:"5.5.49-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-common", reference:"5.5.49-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-server", reference:"5.5.49-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-server-5.5", reference:"5.5.49-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-server-core-5.5", reference:"5.5.49-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-source-5.5", reference:"5.5.49-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-testsuite-5.5", reference:"5.5.49-0+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
