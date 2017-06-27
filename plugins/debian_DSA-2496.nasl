#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2496. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59774);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/02/16 15:37:38 $");

  script_cve_id("CVE-2012-0540", "CVE-2012-0583", "CVE-2012-1688", "CVE-2012-1689", "CVE-2012-1690", "CVE-2012-1703", "CVE-2012-1734", "CVE-2012-2102", "CVE-2012-2122", "CVE-2012-2749");
  script_bugtraq_id(53058, 53061, 53067, 53074, 53911);
  script_osvdb_id(81373, 81374, 81376, 81378, 82804);
  script_xref(name:"DSA", value:"2496");

  script_name(english:"Debian DSA-2496-1 : mysql-5.1 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Due to the non-disclosure of security patch information from
    Oracle, we are forced to ship an upstream version update of MySQL
    5.1. There are several known incompatible changes, which are
    listed in /usr/share/doc/mysql-server/NEWS.Debian.gz.

Several issues have been discovered in the MySQL database server. The
vulnerabilities are addressed by upgrading MySQL to a new upstream
version, 5.1.63, which includes additional changes, such as
performance improvements and corrections for data loss defects. These
changes are described in the MySQL release notes.

 CVE-2012-2122, an authentication bypass vulnerability, occurs only
 when MySQL has been built in with certain optimisations enabled. The
 packages in Debian stable (squeeze) are not known to be affected by
 this vulnerability. It is addressed in this update nonetheless, so
 future rebuilds will not become vulnerable to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=670636"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=677018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-x.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-2122"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/mysql-5.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2496"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the MySQL packages.

For the stable distribution (squeeze), these problems have been fixed
in version 5.1.63-0+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-5.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/29");
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
if (deb_check(release:"6.0", prefix:"libmysqlclient-dev", reference:"5.1.63-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libmysqlclient16", reference:"5.1.63-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libmysqld-dev", reference:"5.1.63-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libmysqld-pic", reference:"5.1.63-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-client", reference:"5.1.63-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-client-5.1", reference:"5.1.63-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-common", reference:"5.1.63-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-server", reference:"5.1.63-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-server-5.1", reference:"5.1.63-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-server-core-5.1", reference:"5.1.63-0+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
