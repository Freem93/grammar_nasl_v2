#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-483. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15320);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/05/05 16:01:12 $");

  script_cve_id("CVE-2004-0381", "CVE-2004-0388");
  script_bugtraq_id(9976, 10142);
  script_osvdb_id(6420, 6421);
  script_xref(name:"DSA", value:"483");

  script_name(english:"Debian DSA-483-1 : mysql - insecure temporary file creation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities have been discovered in mysql, a common database
system. Two scripts contained in the package don't create temporary
files in a secure fashion. This could allow a local attacker to
overwrite files with the privileges of the user invoking the MySQL
server, which is often the root user. The Common Vulnerabilities and
Exposures identifies the following problems :

  - CAN-2004-0381
    The script mysqlbug in MySQL allows local users to
    overwrite arbitrary files via a symlink attack.

  - CAN-2004-0388

    The script mysqld_multi in MySQL allows local users to
    overwrite arbitrary files via a symlink attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-483"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mysql, mysql-dfsg and related packages.

For the stable distribution (woody) these problems have been fixed in
version 3.23.49-8.6."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/03/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"libmysqlclient10", reference:"3.23.49-8.6")) flag++;
if (deb_check(release:"3.0", prefix:"libmysqlclient10-dev", reference:"3.23.49-8.6")) flag++;
if (deb_check(release:"3.0", prefix:"mysql-client", reference:"3.23.49-8.6")) flag++;
if (deb_check(release:"3.0", prefix:"mysql-common", reference:"3.23.49-8.6")) flag++;
if (deb_check(release:"3.0", prefix:"mysql-server", reference:"3.23.49-8.6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
