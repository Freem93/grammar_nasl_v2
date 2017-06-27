#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3385. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86679);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/11/02 14:33:25 $");

  script_cve_id("CVE-2015-4792", "CVE-2015-4802", "CVE-2015-4815", "CVE-2015-4816", "CVE-2015-4819", "CVE-2015-4826", "CVE-2015-4830", "CVE-2015-4836", "CVE-2015-4858", "CVE-2015-4861", "CVE-2015-4870", "CVE-2015-4879", "CVE-2015-4895", "CVE-2015-4913");
  script_xref(name:"DSA", value:"3385");

  script_name(english:"Debian DSA-3385-1 : mariadb-10.0 - security update");
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
upstream version 10.0.22. Please see the MariaDB 10.0 Release Notes
for further details :

  -
    https://mariadb.com/kb/en/mariadb/mariadb-10021-release-
    notes/
  -
    https://mariadb.com/kb/en/mariadb/mariadb-10022-release-
    notes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=802874"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/mariadb/mariadb-10021-release-notes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/mariadb/mariadb-10022-release-notes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/mariadb-10.0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3385"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mariadb-10.0 packages.

For the stable distribution (jessie), these problems have been fixed
in version 10.0.22-0+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/02");
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
if (deb_check(release:"8.0", prefix:"libmariadbd-dev", reference:"10.0.22-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-client", reference:"10.0.22-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-client-10.0", reference:"10.0.22-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-client-core-10.0", reference:"10.0.22-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-common", reference:"10.0.22-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-connect-engine-10.0", reference:"10.0.22-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-oqgraph-engine-10.0", reference:"10.0.22-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-server", reference:"10.0.22-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-server-10.0", reference:"10.0.22-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-server-core-10.0", reference:"10.0.22-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-test", reference:"10.0.22-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-test-10.0", reference:"10.0.22-0+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
