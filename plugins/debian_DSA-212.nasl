#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-212. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15049);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2002-1373", "CVE-2002-1374", "CVE-2002-1375", "CVE-2002-1376");
  script_bugtraq_id(6368, 6373, 6375);
  script_xref(name:"DSA", value:"212");

  script_name(english:"Debian DSA-212-1 : mysql - multiple problems");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"While performing an audit of MySQL e-matters found several problems :

signed/unsigned problem in COM_TABLE_DUMP Two sizes were taken as
signed integers from a request and then cast to unsigned integers
without checking for negative numbers. Since the resulting numbers
where used for a memcpy() operation this could lead to memory
corruption.Password length handling in COM_CHANGE_USER When
re-authenticating to a different user MySQL did not perform all checks
that are performed on initial authentication. This created two
problems :

  - it allowed for single-character password brute forcing
    (as was fixed in February 2000 for initial login) which
    could be used by a normal user to gain root privileges
    to the database
  - it was possible to overflow the password buffer and
    force the server to execute arbitrary code

read_rows() overflow in libmysqlclient When processing the rows
returned by a SQL server there was no check for overly large rows or
terminating NUL characters. This can be used to exploit SQL clients if
they connect to a compromised MySQL server.read_one_row() overflow in
libmysqlclient When processing a row as returned by a SQL server the
returned field sizes were not verified. This can be used to exploit
SQL clients if they connect to a compromised MySQL server.


For Debian GNU/Linux 3.0/woody this has been fixed in version
3.23.49-8.2 and version 3.22.32-6.3 for Debian GNU/Linux 2.2/potato."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-212"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the mysql packages as soon as possible."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
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
if (deb_check(release:"2.2", prefix:"mysql-client", reference:"3.22.32-6.3")) flag++;
if (deb_check(release:"2.2", prefix:"mysql-doc", reference:"3.22.32-6.3")) flag++;
if (deb_check(release:"2.2", prefix:"mysql-server", reference:"3.22.32-6.3")) flag++;
if (deb_check(release:"3.0", prefix:"libmysqlclient10", reference:"3.23.49-8.2")) flag++;
if (deb_check(release:"3.0", prefix:"libmysqlclient10-dev", reference:"3.23.49-8.2")) flag++;
if (deb_check(release:"3.0", prefix:"mysql-client", reference:"3.23.49-8.2")) flag++;
if (deb_check(release:"3.0", prefix:"mysql-common", reference:"3.23.49-8.2")) flag++;
if (deb_check(release:"3.0", prefix:"mysql-doc", reference:"3.23.49-8.2")) flag++;
if (deb_check(release:"3.0", prefix:"mysql-server", reference:"3.23.49-8.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
