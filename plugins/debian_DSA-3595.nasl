#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3595. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91474);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/06 20:25:09 $");

  script_cve_id("CVE-2016-0640", "CVE-2016-0641", "CVE-2016-0643", "CVE-2016-0644", "CVE-2016-0646", "CVE-2016-0647", "CVE-2016-0648", "CVE-2016-0649", "CVE-2016-0650", "CVE-2016-0655", "CVE-2016-0666", "CVE-2016-0668");
  script_osvdb_id(137324, 137325, 137326, 137328, 137336, 137337, 137339, 137341, 137342, 137344, 137348, 137349);
  script_xref(name:"DSA", value:"3595");

  script_name(english:"Debian DSA-3595-1 : mariadb-10.0 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several issues have been discovered in the MariaDB database server.
The vulnerabilities are addressed by upgrading MariaDB to the new
upstream version 10.0.25. Please see the MariaDB 10.0 Release Notes
for further details :

  -
    https://mariadb.com/kb/en/mariadb/mariadb-10024-release-
    notes/
  -
    https://mariadb.com/kb/en/mariadb/mariadb-10025-release-
    notes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=823325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/mariadb/mariadb-10024-release-notes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/mariadb/mariadb-10025-release-notes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/mariadb-10.0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3595"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mariadb-10.0 packages.

For the stable distribution (jessie), these problems have been fixed
in version 10.0.25-0+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/06");
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
if (deb_check(release:"8.0", prefix:"libmariadbd-dev", reference:"10.0.25-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-client", reference:"10.0.25-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-client-10.0", reference:"10.0.25-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-client-core-10.0", reference:"10.0.25-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-common", reference:"10.0.25-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-connect-engine-10.0", reference:"10.0.25-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-oqgraph-engine-10.0", reference:"10.0.25-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-server", reference:"10.0.25-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-server-10.0", reference:"10.0.25-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-server-core-10.0", reference:"10.0.25-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-test", reference:"10.0.25-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-test-10.0", reference:"10.0.25-0+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
