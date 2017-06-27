#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2845. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72010);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/16 15:43:10 $");

  script_cve_id("CVE-2013-5908", "CVE-2014-0386", "CVE-2014-0393", "CVE-2014-0401", "CVE-2014-0402", "CVE-2014-0412", "CVE-2014-0437");
  script_bugtraq_id(64849, 64877, 64880, 64896, 64898, 64904, 64908);
  script_xref(name:"DSA", value:"2845");

  script_name(english:"Debian DSA-2845-1 : mysql-5.1 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This DSA updates the MySQL 5.1 database to 5.1.73. This fixes multiple
unspecified security problems in MySQL:
http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.h
tml"
  );
  # http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?17c46362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/mysql-5.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2845"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mysql-5.1 packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 5.1.73-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-5.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libmysqlclient-dev", reference:"5.1.73-1")) flag++;
if (deb_check(release:"6.0", prefix:"libmysqlclient16", reference:"5.1.73-1")) flag++;
if (deb_check(release:"6.0", prefix:"libmysqld-dev", reference:"5.1.73-1")) flag++;
if (deb_check(release:"6.0", prefix:"libmysqld-pic", reference:"5.1.73-1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-client", reference:"5.1.73-1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-client-5.1", reference:"5.1.73-1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-common", reference:"5.1.73-1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-server", reference:"5.1.73-1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-server-5.1", reference:"5.1.73-1")) flag++;
if (deb_check(release:"6.0", prefix:"mysql-server-core-5.1", reference:"5.1.73-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
