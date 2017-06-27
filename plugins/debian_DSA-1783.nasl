#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1783. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38642);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-3963", "CVE-2008-4456");
  script_xref(name:"DSA", value:"1783");

  script_name(english:"Debian DSA-1783-1 : mysql-dfsg-5.0 - multiple vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been identified affecting MySQL, a
relational database server, and its associated interactive client
application. The Common Vulnerabilities and Exposures project
identifies the following two problems :

  - CVE-2008-3963
    Kay Roepke reported that the MySQL server would not
    properly handle an empty bit-string literal in a SQL
    statement, allowing an authenticated remote attacker to
    cause a denial of service (a crash) in mysqld. This
    issue affects the oldstable distribution (etch), but not
    the stable distribution (lenny).

  - CVE-2008-4456
    Thomas Henlich reported that the MySQL commandline
    client application did not encode HTML special
    characters when run in HTML output mode (that is, 'mysql
    --html ...'). This could potentially lead to cross-site
    scripting or unintended script privilege escalation if
    the resulting output is viewed in a browser or
    incorporated into a website."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=498362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3963"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1783"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mysql-dfsg-5.0 packages.

For the old stable distribution (etch), these problems have been fixed
in version 5.0.32-7etch10.

For the stable distribution (lenny), these problems have been fixed in
version 5.0.51a-24+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_cwe_id(79, 134);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-dfsg-5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libmysqlclient15-dev", reference:"5.0.32-7etch10")) flag++;
if (deb_check(release:"4.0", prefix:"libmysqlclient15off", reference:"5.0.32-7etch10")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-client", reference:"5.0.32-7etch10")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-client-5.0", reference:"5.0.32-7etch10")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-common", reference:"5.0.32-7etch10")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-server", reference:"5.0.32-7etch10")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-server-4.1", reference:"5.0.32-7etch10")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-server-5.0", reference:"5.0.32-7etch10")) flag++;
if (deb_check(release:"5.0", prefix:"libmysqlclient15-dev", reference:"5.0.51a-24+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libmysqlclient15off", reference:"5.0.51a-24+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"mysql-client", reference:"5.0.51a-24+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"mysql-client-5.0", reference:"5.0.51a-24+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"mysql-common", reference:"5.0.51a-24+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"mysql-server", reference:"5.0.51a-24+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"mysql-server-5.0", reference:"5.0.51a-24+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
