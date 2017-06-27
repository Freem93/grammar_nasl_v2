#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-303. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15140);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/18 00:07:15 $");

  script_cve_id("CVE-2003-0073", "CVE-2003-0150");
  script_bugtraq_id(7052);
  script_xref(name:"DSA", value:"303");

  script_name(english:"Debian DSA-303-1 : mysql - privilege escalation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CAN-2003-0073: The mysql package contains a bug whereby dynamically
allocated memory is freed more than once, which could be deliberately
triggered by an attacker to cause a crash, resulting in a denial of
service condition. In order to exploit this vulnerability, a valid
username and password combination for access to the MySQL server is
required.

CAN-2003-0150: The mysql package contains a bug whereby a malicious
user, granted certain permissions within mysql, could create a
configuration file which would cause the mysql server to run as root,
or any other user, rather than the mysql user."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-303"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the stable distribution (woody) both problems have been fixed in
version 3.23.49-8.4.

The old stable distribution (potato) is only affected by
CAN-2003-0150, and this has been fixed in version 3.22.32-6.4.

We recommend that you update your mysql package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"mysql-client", reference:"3.22.32-6.4")) flag++;
if (deb_check(release:"2.2", prefix:"mysql-doc", reference:"3.22.32-6.4")) flag++;
if (deb_check(release:"2.2", prefix:"mysql-server", reference:"3.22.32-6.4")) flag++;
if (deb_check(release:"3.0", prefix:"libmysqlclient10", reference:"3.23.49-8.4")) flag++;
if (deb_check(release:"3.0", prefix:"libmysqlclient10-dev", reference:"3.23.49-8.4")) flag++;
if (deb_check(release:"3.0", prefix:"mysql-client", reference:"3.23.49-8.4")) flag++;
if (deb_check(release:"3.0", prefix:"mysql-common", reference:"3.23.49-8.4")) flag++;
if (deb_check(release:"3.0", prefix:"mysql-doc", reference:"3.23.49-8.4")) flag++;
if (deb_check(release:"3.0", prefix:"mysql-server", reference:"3.23.49-8.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
