#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1478. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30125);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/04/28 18:23:48 $");

  script_cve_id("CVE-2008-0226", "CVE-2008-0227");
  script_osvdb_id(41195, 41197);
  script_xref(name:"DSA", value:"1478");

  script_name(english:"Debian DSA-1478-1 : mysql-dfsg-5.0 - buffer overflows");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Luigi Auriemma discovered two buffer overflows in YaSSL, an SSL
implementation included in the MySQL database package, which could
lead to denial of service and possibly the execution of arbitrary
code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1478"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mysql-dfsg-5.0 package.

The old stable distribution (sarge) doesn't contain mysql-dfsg-5.0.

For the stable distribution (etch), these problems have been fixed in
version 5.0.32-7etch5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MySQL yaSSL SSL Hello Message Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-dfsg-5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libmysqlclient15-dev", reference:"5.0.32-7etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libmysqlclient15off", reference:"5.0.32-7etch5")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-client", reference:"5.0.32-7etch5")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-client-5.0", reference:"5.0.32-7etch5")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-common", reference:"5.0.32-7etch5")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-server", reference:"5.0.32-7etch5")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-server-4.1", reference:"5.0.32-7etch5")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-server-5.0", reference:"5.0.32-7etch5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
