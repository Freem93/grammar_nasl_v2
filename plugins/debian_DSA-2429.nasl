#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2429. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(58277);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2011-2262", "CVE-2012-0075", "CVE-2012-0087", "CVE-2012-0101", "CVE-2012-0102", "CVE-2012-0112", "CVE-2012-0113", "CVE-2012-0114", "CVE-2012-0115", "CVE-2012-0116", "CVE-2012-0118", "CVE-2012-0119", "CVE-2012-0120", "CVE-2012-0484", "CVE-2012-0485", "CVE-2012-0490", "CVE-2012-0492");
  script_bugtraq_id(51488, 51493, 51502, 51504, 51505, 51508, 51509, 51511, 51512, 51513, 51515, 51516, 51517, 51519, 51520, 51524, 51526);
  script_osvdb_id(78368, 78369, 78370, 78372, 78373, 78374, 78376, 78377, 78378, 78379, 78380, 78381, 78382, 78383, 78388, 78391, 78393);
  script_xref(name:"DSA", value:"2429");

  script_name(english:"Debian DSA-2429-1 : mysql-5.1 - several vulnerabilities");
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

Several security vulnerabilities were discovered in MySQL, a database
management system. The vulnerabilities are addressed by upgrading
MySQL to a new upstream version, 5.1.61, which includes additional
changes, such as performance improvements and corrections for data
loss defects. These changes are described in the MySQL release notes
at: ."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=659687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/mysql-5.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2429"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mysql-5.1 packages.

For the stable distribution (squeeze), these problems have been fixed
in version 5.1.61-0+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-5.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libmysqlclient-dev", reference:"5.1.61-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libmysqlclient16", reference:"5.1.61-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libmysqld-dev", reference:"5.1.61-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libmysqld-pic", reference:"5.1.61-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-client", reference:"5.1.61-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-client-5.1", reference:"5.1.61-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-common", reference:"5.1.61-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-server", reference:"5.1.61-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-server-5.1", reference:"5.1.61-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-server-core-5.1", reference:"5.1.61-0+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
