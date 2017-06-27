#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3621. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92381);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/07/21 13:58:10 $");

  script_cve_id("CVE-2015-2575");
  script_osvdb_id(120721);
  script_xref(name:"DSA", value:"3621");

  script_name(english:"Debian DSA-3621-1 : mysql-connector-java - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability was discovered in mysql-connector-java, a Java
database (JDBC) driver for MySQL, which may result in unauthorized
update, insert or delete access to some MySQL Connectors accessible
data as well as read access to a subset of MySQL Connectors accessible
data. The vulnerability was addressed by upgrading
mysql-connector-java to the new upstream version 5.1.39, which
includes additional changes, such as bug fixes, new features, and
possibly incompatible changes. Please see the MySQL Connector/J
Release Notes and Oracle's Critical Patch Update advisory for further
details :

  -
    https://dev.mysql.com/doc/relnotes/connector-j/5.1/en/ne
    ws-5-1.html
  -
    http://www.oracle.com/technetwork/topics/security/cpuapr
    2015-2365600.html#AppendixMSQL"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://dev.mysql.com/doc/relnotes/connector-j/5.1/en/news-5-1.html"
  );
  # http://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html#AppendixMSQL
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c4f2e20f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/mysql-connector-java"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3621"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mysql-connector-java packages.

For the stable distribution (jessie), this problem has been fixed in
version 5.1.39-1~deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-connector-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");
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
if (deb_check(release:"8.0", prefix:"libmysql-java", reference:"5.1.39-1~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
