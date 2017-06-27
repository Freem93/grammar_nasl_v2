#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-707. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18042);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/18 00:15:58 $");

  script_cve_id("CVE-2004-0957", "CVE-2005-0709", "CVE-2005-0710", "CVE-2005-0711");
  script_bugtraq_id(12781);
  script_osvdb_id(10959, 14676, 14677, 14678);
  script_xref(name:"DSA", value:"707");

  script_name(english:"Debian DSA-707-1 : mysql - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in MySQL, a popular
database. The Common Vulnerabilities and Exposures project identifies
the following problems :

  - CAN-2004-0957
    Sergei Golubchik discovered a problem in the access
    handling for similar named databases. If a user is
    granted privileges to a database with a name containing
    an underscore ('_'), the user also gains privileges to
    other databases with similar names.

  - CAN-2005-0709

    Stefano Di Paola discovered that MySQL allows remote
    authenticated users with INSERT and DELETE privileges to
    execute arbitrary code by using CREATE FUNCTION to
    access libc calls.

  - CAN-2005-0710

    Stefano Di Paola discovered that MySQL allows remote
    authenticated users with INSERT and DELETE privileges to
    bypass library path restrictions and execute arbitrary
    libraries by using INSERT INTO to modify the mysql.func
    table.

  - CAN-2005-0711

    Stefano Di Paola discovered that MySQL uses predictable
    file names when creating temporary tables, which allows
    local users with CREATE TEMPORARY TABLE privileges to
    overwrite arbitrary files via a symlink attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=285276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=296674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=300158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-707"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mysql packages.

For the stable distribution (woody) these problems have been fixed in
version 3.23.49-8.11."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/05/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"libmysqlclient10", reference:"3.23.49-8.11")) flag++;
if (deb_check(release:"3.0", prefix:"libmysqlclient10-dev", reference:"3.23.49-8.11")) flag++;
if (deb_check(release:"3.0", prefix:"mysql-client", reference:"3.23.49-8.11")) flag++;
if (deb_check(release:"3.0", prefix:"mysql-common", reference:"3.23.49-8.11")) flag++;
if (deb_check(release:"3.0", prefix:"mysql-doc", reference:"3.23.49-8.5")) flag++;
if (deb_check(release:"3.0", prefix:"mysql-server", reference:"3.23.49-8.11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
