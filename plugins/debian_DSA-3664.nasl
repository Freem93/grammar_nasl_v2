#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3664. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93419);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/06 20:25:09 $");

  script_cve_id("CVE-2016-5426", "CVE-2016-5427", "CVE-2016-6172");
  script_osvdb_id(141065, 143963, 143964);
  script_xref(name:"DSA", value:"3664");

  script_name(english:"Debian DSA-3664-1 : pdns - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in pdns, an
authoritative DNS server. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2016-5426 / CVE-2016-5427
    Florian Heinz and Martin Kluge reported that the
    PowerDNS Authoritative Server accepts queries with a
    qname's length larger than 255 bytes and does not
    properly handle dot inside labels. A remote,
    unauthenticated attacker can take advantage of these
    flaws to cause abnormal load on the PowerDNS backend by
    sending specially crafted DNS queries, potentially
    leading to a denial of service.

  - CVE-2016-6172
    It was reported that a malicious primary DNS server can
    crash a secondary PowerDNS server due to improper
    restriction of zone size limits. This update adds a
    feature to limit AXFR sizes in response to this flaw."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=830808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5426"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-5427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-6172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/pdns"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3664"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the pdns packages.

For the stable distribution (jessie), these problems have been fixed
in version 3.4.1-4+deb8u6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/12");
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
if (deb_check(release:"8.0", prefix:"pdns-backend-geo", reference:"3.4.1-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-ldap", reference:"3.4.1-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-lmdb", reference:"3.4.1-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-lua", reference:"3.4.1-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-mydns", reference:"3.4.1-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-mysql", reference:"3.4.1-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-pgsql", reference:"3.4.1-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-pipe", reference:"3.4.1-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-remote", reference:"3.4.1-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-sqlite3", reference:"3.4.1-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-server", reference:"3.4.1-4+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-server-dbg", reference:"3.4.1-4+deb8u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
