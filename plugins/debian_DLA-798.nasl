#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-798-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96779);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/01/26 14:48:47 $");

  script_cve_id("CVE-2016-2120", "CVE-2016-7068", "CVE-2016-7072", "CVE-2016-7073", "CVE-2016-7074");
  script_osvdb_id(150141, 150143, 150148, 150149, 150150);

  script_name(english:"Debian DLA-798-1 : pdns security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in pdns, an
authoritative DNS server. The Common Vulnerabilities and Exposures
project identifies the following problems :

CVE-2016-2120

Mathieu Lafon discovered that pdns does not properly validate records
in zones. An authorized user can take advantage of this flaw to crash
server by inserting a specially crafted record in a zone under their
control and then sending a DNS query for that record.

CVE-2016-7068

Florian Heinz and Martin Kluge reported that pdns parses all records
present in a query regardless of whether they are needed or even
legitimate, allowing a remote, unauthenticated attacker to cause an
abnormal CPU usage load on the pdns server, resulting in a partial
denial of service if the system becomes overloaded.

CVE-2016-7072

Mongo discovered that the webserver in pdns is susceptible to a
denial of service vulnerability. A remote, unauthenticated attacker to
cause a denial of service by opening a large number of f TCP
connections to the web server.

CVE-2016-7073 / CVE-2016-7074

Mongo discovered that pdns does not sufficiently validate TSIG
signatures, allowing an attacker in position of man-in-the-middle to
alter the content of an AXFR.

For Debian 7 'Wheezy', these problems have been fixed in version
3.1-4.1+deb7u3.

We recommend that you upgrade your pdns packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/01/msg00033.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/pdns"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns-backend-geo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns-backend-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns-backend-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns-backend-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns-backend-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns-backend-pipe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns-backend-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns-backend-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns-server-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/26");
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
if (deb_check(release:"7.0", prefix:"pdns-backend-geo", reference:"3.1-4.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"pdns-backend-ldap", reference:"3.1-4.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"pdns-backend-lua", reference:"3.1-4.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"pdns-backend-mysql", reference:"3.1-4.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"pdns-backend-pgsql", reference:"3.1-4.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"pdns-backend-pipe", reference:"3.1-4.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"pdns-backend-sqlite", reference:"3.1-4.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"pdns-backend-sqlite3", reference:"3.1-4.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"pdns-server", reference:"3.1-4.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"pdns-server-dbg", reference:"3.1-4.1+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
