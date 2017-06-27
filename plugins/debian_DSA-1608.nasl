#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1608. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33492);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/05 14:49:55 $");

  script_cve_id("CVE-2008-2079");
  script_bugtraq_id(29106);
  script_xref(name:"DSA", value:"1608");

  script_name(english:"Debian DSA-1608-1 : mysql-dfsg-5.0 - authorization bypass");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sergei Golubchik discovered that MySQL, a widely-deployed database
server, did not properly validate optional data or index directory
paths given in a CREATE TABLE statement, nor would it (under proper
conditions) prevent two databases from using the same paths for data
or index files. This permits an authenticated user with authorization
to create tables in one database to read, write or delete data from
tables subsequently created in other databases, regardless of other
GRANT authorizations. The Common Vulnerabilities and Exposures project
identifies this weakness as CVE-2008-2079."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=480292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1608"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mysql-dfsg-5.0 packages.

For the stable distribution (etch), this problem has been fixed in
version 5.0.32-7etch6. Note that the fix applied will have the
consequence of disallowing the selection of data or index paths under
the database root, which on a Debian system is /var/lib/mysql;
database administrators needing to control the placement of these
files under that location must do so through other means."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-dfsg-5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/15");
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
if (deb_check(release:"4.0", prefix:"libmysqlclient15-dev", reference:"5.0.32-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"libmysqlclient15off", reference:"5.0.32-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-client", reference:"5.0.32-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-client-5.0", reference:"5.0.32-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-common", reference:"5.0.32-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-server", reference:"5.0.32-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-server-4.1", reference:"5.0.32-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-server-5.0", reference:"5.0.32-7etch6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
