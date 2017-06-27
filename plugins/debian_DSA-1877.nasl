#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1877. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44742);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/05/17 23:54:22 $");

  script_cve_id("CVE-2009-2446");
  script_bugtraq_id(35609);
  script_xref(name:"DSA", value:"1877");

  script_name(english:"Debian DSA-1877-1 : mysql-dfsg-5.0 - denial of service/execution of arbitrary code");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"In MySQL 4.0.0 through 5.0.83, multiple format string vulnerabilities
in the dispatch_command() function in libmysqld/sql_parse.cc in mysqld
allow remote authenticated users to cause a denial of service (daemon
crash) and potentially the execution of arbitrary code via format
string specifiers in a database name in a COM_CREATE_DB or COM_DROP_DB
request."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=536726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1877"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mysql packages.

For the stable distribution (lenny), this problem has been fixed in
version 5.0.51a-24+lenny2.

For the old stable distribution (etch), this problem has been fixed in
version 5.0.32-7etch11."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(134);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-dfsg-5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libmysqlclient15-dev", reference:"5.0.32-7etch11")) flag++;
if (deb_check(release:"4.0", prefix:"libmysqlclient15off", reference:"5.0.32-7etch11")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-client", reference:"5.0.32-7etch11")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-client-5.0", reference:"5.0.32-7etch11")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-common", reference:"5.0.32-7etch11")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-server", reference:"5.0.32-7etch11")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-server-4.1", reference:"5.0.32-7etch11")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-server-5.0", reference:"5.0.32-7etch11")) flag++;
if (deb_check(release:"5.0", prefix:"libmysqlclient15-dev", reference:"5.0.51a-24+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libmysqlclient15off", reference:"5.0.51a-24+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"mysql-client", reference:"5.0.51a-24+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"mysql-client-5.0", reference:"5.0.51a-24+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"mysql-common", reference:"5.0.51a-24+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"mysql-server", reference:"5.0.51a-24+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"mysql-server-5.0", reference:"5.0.51a-24+lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
