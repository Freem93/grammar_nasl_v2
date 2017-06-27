#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-227-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83905);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/05/05 14:49:54 $");

  script_cve_id("CVE-2015-3165", "CVE-2015-3166", "CVE-2015-3167");
  script_bugtraq_id(74787, 74789, 74790);
  script_osvdb_id(122456, 122457, 122458);

  script_name(english:"Debian DLA-227-1 : postgresql-8.4 update");
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
fixes that were applied upstream to the 9.0.20 version, backported to
8.4.22 which was the last version officially released by the
PostgreSQL developers. This LTS effort for squeeze-lts is a community
project sponsored by credativ GmbH.

CVE-2015-3165: Remote crash SSL clients disconnecting just before the
authentication timeout expires can cause the server to crash.

CVE-2015-3166: Information exposure The replacement implementation of
snprintf() failed to check for errors reported by the underlying
system library calls; the main case that might be missed is
out-of-memory situations. In the worst case this might lead to
information exposure.

CVE-2015-3167: Possible side-channel key exposure In contrib/pgcrypto,
some cases of decryption with an incorrect key could report other
error message texts. Fix by using a one-size-fits-all message.

Note that the next round of minor releases for PostgreSQL have already
been scheduled for early June 2015. There will be a corresponding
8.4.22lts3 update at the same time.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/05/msg00018.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/postgresql-8.4"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/01");
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
if (deb_check(release:"6.0", prefix:"libecpg-compat3", reference:"8.4.22lts2-0+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libecpg-dev", reference:"8.4.22lts2-0+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libecpg6", reference:"8.4.22lts2-0+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libpgtypes3", reference:"8.4.22lts2-0+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libpq-dev", reference:"8.4.22lts2-0+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libpq5", reference:"8.4.22lts2-0+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql", reference:"8.4.22lts2-0+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-8.4", reference:"8.4.22lts2-0+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-client", reference:"8.4.22lts2-0+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-client-8.4", reference:"8.4.22lts2-0+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-contrib", reference:"8.4.22lts2-0+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-contrib-8.4", reference:"8.4.22lts2-0+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-doc", reference:"8.4.22lts2-0+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-doc-8.4", reference:"8.4.22lts2-0+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-plperl-8.4", reference:"8.4.22lts2-0+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-plpython-8.4", reference:"8.4.22lts2-0+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-pltcl-8.4", reference:"8.4.22lts2-0+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"postgresql-server-dev-8.4", reference:"8.4.22lts2-0+deb6u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
