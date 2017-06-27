#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1997. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44861);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2009-4019", "CVE-2009-4030", "CVE-2009-4484");
  script_bugtraq_id(37075, 37640, 37943);
  script_osvdb_id(60488, 60489, 60665, 61956);
  script_xref(name:"DSA", value:"1997");

  script_name(english:"Debian DSA-1997-1 : mysql-dfsg-5.0 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the MySQL database
server. The Common Vulnerabilities and Exposures project identifies
the following problems :

  - CVE-2009-4019
    Domas Mituzas discovered that mysqld does not properly
    handle errors during execution of certain SELECT
    statements with subqueries, and does not preserve
    certain null_value flags during execution of statements
    that use the GeomFromWKB function, which allows remote
    authenticated users to cause a denial of service (daemon
    crash) via a crafted statement.

  - CVE-2009-4030
    Sergei Golubchik discovered that MySQL allows local
    users to bypass certain privilege checks by calling
    CREATE TABLE on a MyISAM table with modified DATA
    DIRECTORY or INDEX DIRECTORY arguments that are
    originally associated with pathnames without symlinks,
    and that can point to tables created at a future time at
    which a pathname is modified to contain a symlink to a
    subdirectory of the MySQL data home directory.

  - CVE-2009-4484
    Multiple stack-based buffer overflows in the
    CertDecoder::GetName function in src/asn.cpp in TaoCrypt
    in yaSSL before 1.9.9, as used in mysqld, allow remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and daemon crash) by
    establishing an SSL connection and sending an X.509
    client certificate with a crafted name field."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4030"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-1997"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mysql-dfsg-5.0 packages.

For the oldstable distribution (etch), these problems have been fixed
in version 5.0.32-7etch12

For the stable distribution (lenny), these problems have been fixed in
version 5.0.51a-24+lenny3"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MySQL yaSSL CertDecoder::GetName Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(59, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-dfsg-5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libmysqlclient15-dev", reference:"5.0.32-7etch12")) flag++;
if (deb_check(release:"4.0", prefix:"libmysqlclient15off", reference:"5.0.32-7etch12")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-client", reference:"5.0.32-7etch12")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-client-5.0", reference:"5.0.32-7etch12")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-common", reference:"5.0.32-7etch12")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-server", reference:"5.0.32-7etch12")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-server-4.1", reference:"5.0.32-7etch12")) flag++;
if (deb_check(release:"4.0", prefix:"mysql-server-5.0", reference:"5.0.32-7etch12")) flag++;
if (deb_check(release:"5.0", prefix:"libmysqlclient15-dev", reference:"5.0.51a-24+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"libmysqlclient15off", reference:"5.0.51a-24+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"mysql-client", reference:"5.0.51a-24+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"mysql-client-5.0", reference:"5.0.51a-24+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"mysql-common", reference:"5.0.51a-24+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"mysql-server", reference:"5.0.51a-24+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"mysql-server-5.0", reference:"5.0.51a-24+lenny3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
