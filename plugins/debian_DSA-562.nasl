#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-562. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15660);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/18 00:11:36 $");

  script_cve_id("CVE-2004-0835", "CVE-2004-0836", "CVE-2004-0837");
  script_osvdb_id(10658, 10659, 10660);
  script_xref(name:"DSA", value:"562");

  script_name(english:"Debian DSA-562-1 : mysql - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several problems have been discovered in MySQL, a commonly used SQL
database on Unix servers. The following problems have been identified
by the Common Vulnerabilities and Exposures Project :

  - CAN-2004-0835
    Oleksandr Byelkin noticed that ALTER TABLE ... RENAME
    checks CREATE/INSERT rights of the old table instead of
    the new one.

  - CAN-2004-0836

    Lukasz Wojtow noticed a buffer overrun in the
    mysql_real_connect function.

  - CAN-2004-0837

    Dean Ellis noticed that multiple threads ALTERing the
    same (or different) MERGE tables to change the UNION can
    cause the server to crash or stall."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-562"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mysql and related packages and restart services linking
against them (e.g. Apache/PHP).

For the stable distribution (woody) these problems have been fixed in
version 3.23.49-8.8."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"libmysqlclient10", reference:"3.23.49-8.8")) flag++;
if (deb_check(release:"3.0", prefix:"libmysqlclient10-dev", reference:"3.23.49-8.8")) flag++;
if (deb_check(release:"3.0", prefix:"mysql-client", reference:"3.23.49-8.8")) flag++;
if (deb_check(release:"3.0", prefix:"mysql-common", reference:"3.23.49-8.8")) flag++;
if (deb_check(release:"3.0", prefix:"mysql-doc", reference:"3.23.49-8.5")) flag++;
if (deb_check(release:"3.0", prefix:"mysql-server", reference:"3.23.49-8.8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
