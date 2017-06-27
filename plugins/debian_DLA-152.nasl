#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-152-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82135);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/05 14:49:54 $");

  script_cve_id("CVE-2014-8161", "CVE-2015-0241", "CVE-2015-0243", "CVE-2015-0244");
  script_bugtraq_id(72538, 72540, 72542, 72543);
  script_osvdb_id(118033, 118035, 118036, 118037, 118038);

  script_name(english:"Debian DLA-152-1 : postgresql-8.4 update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in PostgreSQL, a relational
database server system. The 8.4 branch is EOLed upstream, but still
present in Debian squeeze. This new LTS minor version contains the
fixes that were applied upstream to the 9.0.19 version, backported to
8.4.22 which was the last version officially released by the
PostgreSQL developers. This LTS effort for squeeze-lts is a community
project sponsored by credativ GmbH.

CVE-2014-8161: Information leak A user with limited clearance on a
table might have access to information in columns without SELECT
rights on through server error messages.

CVE-2015-0241: Out of boundaries read/write The function to_char()
might read/write past the end of a buffer. This might crash the server
when a formatting template is processed.

CVE-2015-0243: Buffer overruns in contrib/pgcrypto The pgcrypto module
is vulnerable to stack buffer overrun that might crash the server.

CVE-2015-0244: SQL command injection Emil Lenngren reported that an
attacker can inject SQL commands when the synchronization between
client and server is lost.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/02/msg00006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/postgresql-8.4"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libecpg-compat3", reference:"8.4.22lts1-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libecpg-dev", reference:"8.4.22lts1-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libecpg6", reference:"8.4.22lts1-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libpgtypes3", reference:"8.4.22lts1-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libpq-dev", reference:"8.4.22lts1-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libpq5", reference:"8.4.22lts1-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql", reference:"8.4.22lts1-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-8.4", reference:"8.4.22lts1-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-client", reference:"8.4.22lts1-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-client-8.4", reference:"8.4.22lts1-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-contrib", reference:"8.4.22lts1-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-contrib-8.4", reference:"8.4.22lts1-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-doc", reference:"8.4.22lts1-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-doc-8.4", reference:"8.4.22lts1-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-plperl-8.4", reference:"8.4.22lts1-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-plpython-8.4", reference:"8.4.22lts1-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-pltcl-8.4", reference:"8.4.22lts1-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-server-dev-8.4", reference:"8.4.22lts1-0+deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
