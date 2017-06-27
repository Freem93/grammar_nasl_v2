#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1502. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31146);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2008-0193", "CVE-2008-0194");
  script_osvdb_id(36311, 37292, 37293, 43408, 43594);
  script_xref(name:"DSA", value:"1502");

  script_name(english:"Debian DSA-1502-1 : wordpress - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in wordpress, a
weblog manager. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2007-3238
    Cross-site scripting (XSS) vulnerability in
    functions.php in the default theme in WordPress allows
    remote authenticated administrators to inject arbitrary
    web script or HTML via the PATH_INFO (REQUEST_URI) to
    wp-admin/themes.php.

  - CVE-2007-2821
    SQL injection vulnerability in wp-admin/admin-ajax.php
    in WordPress before 2.2 allows remote attackers to
    execute arbitrary SQL commands via the cookie parameter.

  - CVE-2008-0193
    Cross-site scripting (XSS) vulnerability in
    wp-db-backup.php in WordPress 2.0.11 and earlier allows
    remote attackers to inject arbitrary web script or HTML
    via the backup parameter in a wp-db-backup.php action to
    wp-admin/edit.php.

  - CVE-2008-0194
    Directory traversal vulnerability in wp-db-backup.php in
    WordPress 2.0.3 and earlier allows remote attackers to
    read arbitrary files, delete arbitrary files, and cause
    a denial of service via a .. (dot dot) in the backup
    parameter in a wp-db-backup.php action to
    wp-admin/edit.php.

Wordpress is not present in the oldstable distribution (sarge)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0194"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1502"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wordpress package.

For the stable distribution (etch), these problems have been fixed in
version 2.0.10-1etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(22, 79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"wordpress", reference:"2.0.10-1etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
