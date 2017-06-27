#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3269. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83786);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2015/10/18 04:40:37 $");

  script_cve_id("CVE-2015-3165", "CVE-2015-3166", "CVE-2015-3167");
  script_bugtraq_id(74787, 74789, 74790);
  script_xref(name:"DSA", value:"3269");

  script_name(english:"Debian DSA-3269-1 : postgresql-9.1 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been found in PostgreSQL-9.1, a SQL
database system.

  - CVE-2015-3165 (Remote crash)
    SSL clients disconnecting just before the authentication
    timeout expires can cause the server to crash.

  - CVE-2015-3166 (Information exposure)
    The replacement implementation of snprintf() failed to
    check for errors reported by the underlying system
    library calls; the main case that might be missed is
    out-of-memory situations. In the worst case this might
    lead to information exposure.

  - CVE-2015-3167 (Possible side-channel key exposure)
    In contrib/pgcrypto, some cases of decryption with an
    incorrect key could report other error message texts.
    Fix by using a one-size-fits-all message."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3167"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/postgresql-9.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/postgresql-9.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3269"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the postgresql-9.1 packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 9.1.16-0+deb7u1.

For the stable distribution (jessie), these problems have been fixed
in version 9.1.16-0+deb8u1. (Jessie contains a reduced postgresql-9.1
package; only CVE-2015-3166 is fixed in the produced binary package
postgresql-plperl-9.1. We recommend to upgrade to postgresql-9.4 to
get the full set of fixes. See the Jessie release notes for details.)"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-9.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/26");
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
if (deb_check(release:"7.0", prefix:"libecpg-compat3", reference:"9.1.16-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libecpg-dev", reference:"9.1.16-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libecpg6", reference:"9.1.16-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpgtypes3", reference:"9.1.16-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpq-dev", reference:"9.1.16-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpq5", reference:"9.1.16-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-9.1", reference:"9.1.16-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-9.1-dbg", reference:"9.1.16-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-client-9.1", reference:"9.1.16-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-contrib-9.1", reference:"9.1.16-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-doc-9.1", reference:"9.1.16-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-plperl-9.1", reference:"9.1.16-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-plpython-9.1", reference:"9.1.16-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-plpython3-9.1", reference:"9.1.16-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-pltcl-9.1", reference:"9.1.16-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"postgresql-server-dev-9.1", reference:"9.1.16-0+deb7u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-plperl-9.1", reference:"9.1.16-0+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
