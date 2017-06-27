#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1169. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22711);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/05 14:49:55 $");

  script_cve_id("CVE-2006-4226", "CVE-2006-4380");
  script_bugtraq_id(19559);
  script_osvdb_id(28012, 28296);
  script_xref(name:"DSA", value:"1169");

  script_name(english:"Debian DSA-1169-1 : mysql-dfsg-4.1 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several local vulnerabilities have been discovered in the MySQL
database server. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2006-4226
    Michal Prokopiuk discovered that remote authenticated
    users are permitted to create and access a database if
    the lowercase spelling is the same as one they have been
    granted access to.

  - CVE-2006-4380
    Beat Vontobel discovered that certain queries replicated
    to a slave could crash the client and thus terminate the
    replication."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4226"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4380"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1169"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mysql-server-4.1 package.

For the stable distribution (sarge) these problems have been fixed in
version 4.1.11a-4sarge7. Version 4.0 is not affected by these
problems."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-dfsg-4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libmysqlclient14", reference:"4.1.11a-4sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"libmysqlclient14-dev", reference:"4.1.11a-4sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"mysql-client-4.1", reference:"4.1.11a-4sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"mysql-common-4.1", reference:"4.1.11a-4sarge7")) flag++;
if (deb_check(release:"3.1", prefix:"mysql-server-4.1", reference:"4.1.11a-4sarge7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
