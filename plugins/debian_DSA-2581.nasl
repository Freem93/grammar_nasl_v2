#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2581. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63151);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/02/16 15:37:39 $");

  script_cve_id("CVE-2012-3150", "CVE-2012-3158", "CVE-2012-3160", "CVE-2012-3163", "CVE-2012-3166", "CVE-2012-3167", "CVE-2012-3173", "CVE-2012-3177", "CVE-2012-3180", "CVE-2012-3197", "CVE-2012-5611");
  script_bugtraq_id(55990, 56003, 56005, 56017, 56018, 56021, 56027, 56028, 56036, 56041, 56769);
  script_xref(name:"DSA", value:"2581");

  script_name(english:"Debian DSA-2581-1 : mysql-5.1 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several issues have been discovered in the MySQL database server. The
vulnerabilities are addressed by upgrading MySQL to a new upstream
version, 5.1.66, which includes additional changes, such as
performance improvements and corrections for data loss defects. These
changes are described in the MySQL release notes.

Additionally, CVE-2012-5611 has been fixed in this upload. The
vulnerability (discovered independently by Tomas Hoger from the Red
Hat Security Response Team and 'king cope') is a stack-based buffer
overflow in acl_get() when checking user access to a database. Using a
carefully crafted database name, an already authenticated MySQL user
could make the server crash or even execute arbitrary code as the
mysql system user."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=690778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=695001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-66.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-5611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/mysql-5.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2581"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mysql-5.1 packages.

For the stable distribution (squeeze), this problem has been fixed in
version 5.1.66-0+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-5.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libmysqlclient-dev", reference:"5.1.66-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libmysqlclient16", reference:"5.1.66-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libmysqld-dev", reference:"5.1.66-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libmysqld-pic", reference:"5.1.66-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-client", reference:"5.1.66-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-client-5.1", reference:"5.1.66-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-common", reference:"5.1.66-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-server", reference:"5.1.66-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-server-5.1", reference:"5.1.66-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-server-core-5.1", reference:"5.1.66-0+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
