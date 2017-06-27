#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1413. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28336);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-2583", "CVE-2007-2691", "CVE-2007-2692", "CVE-2007-5925");
  script_osvdb_id(51171);
  script_xref(name:"DSA", value:"1413");

  script_name(english:"Debian DSA-1413-1 : mysql - multiple vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been found in the MySQL database packages
with implications ranging from unauthorized database modifications to
remotely triggered server crashes. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2007-2583
    The in_decimal::set function in item_cmpfunc.cc in MySQL
    before 5.0.40 allows context-dependent attackers to
    cause a denial of service (crash) via a crafted IF
    clause that results in a divide-by-zero error and a NULL
    pointer dereference. (Affects source version 5.0.32.)

  - CVE-2007-2691
    MySQL does not require the DROP privilege for RENAME
    TABLE statements, which allows remote authenticated
    users to rename arbitrary tables. (All supported
    versions affected.)

  - CVE-2007-2692
    The mysql_change_db function does not restore
    THD::db_access privileges when returning from SQL
    SECURITY INVOKER stored routines, which allows remote
    authenticated users to gain privileges. (Affects source
    version 5.0.32.)

  - CVE-2007-3780
    MySQL could be made to overflow a signed char during
    authentication. Remote attackers could use specially
    crafted authentication requests to cause a denial of
    service. (Upstream source versions 4.1.11a and 5.0.32
    affected.)

  - CVE-2007-3782
    Phil Anderton discovered that MySQL did not properly
    verify access privileges when accessing external tables.
    As a result, authenticated users could exploit this to
    obtain UPDATE privileges to external tables. (Affects
    source version 5.0.32.)

  - CVE-2007-5925
    The convert_search_mode_to_innobase function in
    ha_innodb.cc in the InnoDB engine in MySQL 5.1.23-BK and
    earlier allows remote authenticated users to cause a
    denial of service (database crash) via a certain
    CONTAINS operation on an indexed column, which triggers
    an assertion error. (Affects source version 5.0.32.)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=426353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=424778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=424778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=451235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1413"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mysql packages.

For the old stable distribution (sarge), these problems have been
fixed in version 4.0.24-10sarge3 of mysql-dfsg and version
4.1.11a-4sarge8 of mysql-dfsg-4.1.

For the stable distribution (etch), these problems have been fixed in
version 5.0.32-7etch3 of the mysql-dfsg-5.0 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_cwe_id(20, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-dfsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-dfsg-4.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-dfsg-5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libmysqlclient12", reference:"4.0.24-10sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libmysqlclient12-dev", reference:"4.0.24-10sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libmysqlclient14", reference:"4.1.11a-4sarge8")) flag++;
if (deb_check(release:"3.1", prefix:"libmysqlclient14-dev", reference:"4.1.11a-4sarge8")) flag++;
if (deb_check(release:"3.1", prefix:"mysql-client", reference:"4.0.24-10sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"mysql-client-4.1", reference:"4.1.11a-4sarge8")) flag++;
if (deb_check(release:"3.1", prefix:"mysql-common", reference:"4.0.24-10sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"mysql-common-4.1", reference:"4.1.11a-4sarge8")) flag++;
if (deb_check(release:"3.1", prefix:"mysql-server", reference:"4.0.24-10sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"mysql-server-4.1", reference:"4.1.11a-4sarge8")) flag++;
if (deb_check(release:"4.0", prefix:"libmysqlclient15-dev", reference:"5.0.32-7etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libmysqlclient15off", reference:"5.0.32-7etch3")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-client", reference:"5.0.32-7etch3")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-client-5.0", reference:"5.0.32-7etch3")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-common", reference:"5.0.32-7etch3")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-server", reference:"5.0.32-7etch3")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-server-4.1", reference:"5.0.32-7etch3")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-server-5.0", reference:"5.0.32-7etch3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
