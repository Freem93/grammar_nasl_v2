#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-338. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15175);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/18 00:07:15 $");

  script_cve_id("CVE-2003-0500");
  script_bugtraq_id(7974);
  script_xref(name:"DSA", value:"338");

  script_name(english:"Debian DSA-338-1 : proftpd - SQL injection");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"runlevel [runlevel@raregazz.org] reported that ProFTPD's PostgreSQL
authentication module is vulnerable to a SQL injection attack. This
vulnerability could be exploited by a remote, unauthenticated attacker
to execute arbitrary SQL statements, potentially exposing the
passwords of other users, or to connect to ProFTPD as an arbitrary
user without supplying the correct password."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-338"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the stable distribution (woody) this problem has been fixed in
version 1.2.4+1.2.5rc1-5woody2.

We recommend that you update your proftpd package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/06/29");
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
if (deb_check(release:"3.0", prefix:"proftpd", reference:"1.2.4+1.2.5rc1-5woody2")) flag++;
if (deb_check(release:"3.0", prefix:"proftpd-common", reference:"1.2.4+1.2.5rc1-5woody2")) flag++;
if (deb_check(release:"3.0", prefix:"proftpd-doc", reference:"1.2.4+1.2.5rc1-5woody2")) flag++;
if (deb_check(release:"3.0", prefix:"proftpd-ldap", reference:"1.2.4+1.2.5rc1-5woody2")) flag++;
if (deb_check(release:"3.0", prefix:"proftpd-mysql", reference:"1.2.4+1.2.5rc1-5woody2")) flag++;
if (deb_check(release:"3.0", prefix:"proftpd-pgsql", reference:"1.2.4+1.2.5rc1-5woody2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
