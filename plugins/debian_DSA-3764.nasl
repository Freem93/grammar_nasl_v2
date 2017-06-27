#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3764. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96497);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/01/18 14:49:20 $");

  script_cve_id("CVE-2016-2120", "CVE-2016-7068", "CVE-2016-7072", "CVE-2016-7073", "CVE-2016-7074");
  script_osvdb_id(150141, 150143, 150148, 150149, 150150);
  script_xref(name:"DSA", value:"3764");

  script_name(english:"Debian DSA-3764-1 : pdns - security update");
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

  - CVE-2016-2120
    Mathieu Lafon discovered that pdns does not properly
    validate records in zones. An authorized user can take
    advantage of this flaw to crash server by inserting a
    specially crafted record in a zone under their control
    and then sending a DNS query for that record.

  - CVE-2016-7068
    Florian Heinz and Martin Kluge reported that pdns parses
    all records present in a query regardless of whether
    they are needed or even legitimate, allowing a remote,
    unauthenticated attacker to cause an abnormal CPU usage
    load on the pdns server, resulting in a partial denial
    of service if the system becomes overloaded.

  - CVE-2016-7072
    Mongo discovered that the webserver in pdns is
    susceptible to a denial-of-service vulnerability,
    allowing a remote, unauthenticated attacker to cause a
    denial of service by opening a large number of TCP
    connections to the web server.

  - CVE-2016-7073 / CVE-2016-7074
    Mongo discovered that pdns does not sufficiently
    validate TSIG signatures, allowing an attacker in
    position of man-in-the-middle to alter the content of an
    AXFR."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-7068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-7072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-7073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-7074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/pdns"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2017/dsa-3764"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the pdns packages.

For the stable distribution (jessie), these problems have been fixed
in version 3.4.1-4+deb8u7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/16");
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
if (deb_check(release:"8.0", prefix:"pdns-backend-geo", reference:"3.4.1-4+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-ldap", reference:"3.4.1-4+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-lmdb", reference:"3.4.1-4+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-lua", reference:"3.4.1-4+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-mydns", reference:"3.4.1-4+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-mysql", reference:"3.4.1-4+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-pgsql", reference:"3.4.1-4+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-pipe", reference:"3.4.1-4+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-remote", reference:"3.4.1-4+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-sqlite3", reference:"3.4.1-4+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-server", reference:"3.4.1-4+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-server-dbg", reference:"3.4.1-4+deb8u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
