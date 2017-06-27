#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1370. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26031);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2006-6942", "CVE-2006-6944", "CVE-2007-1325", "CVE-2007-1395", "CVE-2007-2245");
  script_osvdb_id(30470, 30471, 30472, 35050, 58821, 58822, 58823, 58824);
  script_xref(name:"DSA", value:"1370");

  script_name(english:"Debian DSA-1370-1 : phpmyadmin - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in phpMyAdmin, a
program to administrate MySQL over the web. The Common Vulnerabilities
and Exposures project identifies the following problems :

  - CVE-2007-1325
    The PMA_ArrayWalkRecursive function in
    libraries/common.lib.php does not limit recursion on
    arrays provided by users, which allows context-dependent
    attackers to cause a denial of service (web server
    crash) via an array with many dimensions.

  This issue affects only the stable distribution (Etch).

  - CVE-2007-1395
    Incomplete blacklist vulnerability in index.php allows
    remote attackers to conduct cross-site scripting (XSS)
    attacks by injecting arbitrary JavaScript or HTML in a
    (1) db or (2) table parameter value followed by an
    uppercase </SCRIPT> end tag, which bypasses the
    protection against lowercase </script>.

  This issue affects only the stable distribution (Etch).

  - CVE-2007-2245
    Multiple cross-site scripting (XSS) vulnerabilities
    allow remote attackers to inject arbitrary web script or
    HTML via (1) the fieldkey parameter to
    browse_foreigners.php or (2) certain input to the
    PMA_sanitize function.

  - CVE-2006-6942
    Multiple cross-site scripting (XSS) vulnerabilities
    allow remote attackers to inject arbitrary HTML or web
    script via (1) a comment for a table name, as exploited
    through (a) db_operations.php, (2) the db parameter to
    (b) db_create.php, (3) the newname parameter to
    db_operations.php, the (4) query_history_latest, (5)
    query_history_latest_db, and (6) querydisplay_tab
    parameters to (c) querywindow.php, and (7) the pos
    parameter to (d) sql.php.

  This issue affects only the oldstable distribution (Sarge).

  - CVE-2006-6944
    phpMyAdmin allows remote attackers to bypass Allow/Deny
    access rules that use IP addresses via false headers.

  This issue affects only the oldstable distribution (Sarge)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1395"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6942"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1370"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the phpmyadmin packages.

For the old stable distribution (sarge) these problems have been fixed
in version 2.6.2-3sarge5.

For the stable distribution (etch) these problems have been fixed in
version 2.9.1.1-4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:phpmyadmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"phpmyadmin", reference:"2.6.2-3sarge5")) flag++;
if (deb_check(release:"4.0", prefix:"phpmyadmin", reference:"2.9.1.1-4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
