#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-381. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15218);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/04/30 10:43:34 $");

  script_cve_id("CVE-2003-0780");
  script_bugtraq_id(8590);
  script_xref(name:"DSA", value:"381");

  script_name(english:"Debian DSA-381-1 : mysql - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MySQL, a popular relational database system, contains a buffer
overflow condition which could be exploited by a user who has
permission to execute 'ALTER TABLE' commands on the tables in the
'mysql' database. If successfully exploited, this vulnerability could
allow the attacker to execute arbitrary code with the privileges of
the mysqld process (by default, user 'mysql'). Since the 'mysql'
database is used for MySQL's internal record keeping, by default the
mysql administrator 'root' is the only user with permission to alter
its tables."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=210403"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/210403"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-381"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the stable distribution (woody) this problem has been fixed in
version 3.23.49-8.5.

We recommend that you update your mysql package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"libmysqlclient10", reference:"3.23.49-8.5")) flag++;
if (deb_check(release:"3.0", prefix:"libmysqlclient10-dev", reference:"3.23.49-8.5")) flag++;
if (deb_check(release:"3.0", prefix:"mysql-client", reference:"3.23.49-8.5")) flag++;
if (deb_check(release:"3.0", prefix:"mysql-common", reference:"3.23.49-8.5")) flag++;
if (deb_check(release:"3.0", prefix:"mysql-doc", reference:"3.23.49-8.5")) flag++;
if (deb_check(release:"3.0", prefix:"mysql-server", reference:"3.23.49-8.5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
