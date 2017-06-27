#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3306. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84649);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/11/04 16:37:16 $");

  script_cve_id("CVE-2015-5470");
  script_bugtraq_id(74306);
  script_xref(name:"DSA", value:"3306");

  script_name(english:"Debian DSA-3306-1 : pdns - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Toshifumi Sakaguchi discovered that the patch applied to pdns, an
authoritative DNS server, fixing CVE-2015-1868, was insufficient in
some cases, allowing remote attackers to cause a denial of service
(service-affecting CPU spikes and in some cases a crash)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/pdns"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3306"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the pdns packages.

For the stable distribution (jessie), this problem has been fixed in
version 3.4.1-4+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/13");
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
if (deb_check(release:"8.0", prefix:"pdns-backend-geo", reference:"3.4.1-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-ldap", reference:"3.4.1-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-lmdb", reference:"3.4.1-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-lua", reference:"3.4.1-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-mydns", reference:"3.4.1-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-mysql", reference:"3.4.1-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-pgsql", reference:"3.4.1-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-pipe", reference:"3.4.1-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-remote", reference:"3.4.1-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-sqlite3", reference:"3.4.1-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-server", reference:"3.4.1-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-server-dbg", reference:"3.4.1-4+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
