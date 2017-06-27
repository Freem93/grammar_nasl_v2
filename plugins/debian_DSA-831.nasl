#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-831. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19800);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/26 16:04:30 $");

  script_cve_id("CVE-2005-2558");
  script_bugtraq_id(14509);
  script_osvdb_id(18896);
  script_xref(name:"DSA", value:"831");

  script_name(english:"Debian DSA-831-1 : mysql-dfsg - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A stack-based buffer overflow in the init_syms function of MySQL, a
popular database, has been discovered that allows remote authenticated
users who can create user-defined functions to execute arbitrary code
via a long function_name field. The ability to create user-defined
functions is not typically granted to untrusted users.

The following vulnerability matrix shows which version of MySQL in
which distribution has this problem fixed :

                   woody            sarge            sid              
  mysql            3.23.49-8.14     n/a              n/a              
  mysql-dfsg       n/a              4.0.24-10sarge1  4.0.24-10sarge1  
  mysql-dfsg-4.1   n/a              4.1.11a-4sarge2  4.1.14-2         
  mysql-dfsg-5.0   n/a              n/a              5.0.11beta-3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-831"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the mysql-dfsg packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-dfsg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libmysqlclient12", reference:"4.0.24-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libmysqlclient12-dev", reference:"4.0.24-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"mysql-client", reference:"4.0.24-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"mysql-common", reference:"4.0.24-10sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"mysql-server", reference:"4.0.24-10sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
