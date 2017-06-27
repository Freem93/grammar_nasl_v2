#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3335. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85388);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/05/05 16:01:12 $");

  script_cve_id("CVE-2015-5475", "CVE-2015-6506");
  script_osvdb_id(126134, 126135);
  script_xref(name:"DSA", value:"3335");

  script_name(english:"Debian DSA-3335-1 : request-tracker4 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Request Tracker, an extensible trouble-ticket
tracking system is susceptible to a cross-site scripting attack via
the user and group rights management pages (CVE-2015-5475 ) and via
the cryptography interface, allowing an attacker with a
carefully-crafted key to inject JavaScript into RT's user interface.
Installations which use neither GnuPG nor S/MIME are unaffected by the
second cross-site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5475"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5475"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/request-tracker4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/request-tracker4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3335"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the request-tracker4 packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 4.0.7-5+deb7u4. The oldstable distribution (wheezy)
is only affected by CVE-2015-5475.

For the stable distribution (jessie), these problems have been fixed
in version 4.2.8-3+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:request-tracker4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/14");
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
if (deb_check(release:"7.0", prefix:"request-tracker4", reference:"4.0.7-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"rt4-apache2", reference:"4.0.7-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"rt4-clients", reference:"4.0.7-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"rt4-db-mysql", reference:"4.0.7-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"rt4-db-postgresql", reference:"4.0.7-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"rt4-db-sqlite", reference:"4.0.7-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"rt4-fcgi", reference:"4.0.7-5+deb7u4")) flag++;
if (deb_check(release:"8.0", prefix:"request-tracker4", reference:"4.2.8-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"rt4-apache2", reference:"4.2.8-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"rt4-clients", reference:"4.2.8-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"rt4-db-mysql", reference:"4.2.8-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"rt4-db-postgresql", reference:"4.2.8-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"rt4-db-sqlite", reference:"4.2.8-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"rt4-doc-html", reference:"4.2.8-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"rt4-fcgi", reference:"4.2.8-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"rt4-standalone", reference:"4.2.8-3+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
