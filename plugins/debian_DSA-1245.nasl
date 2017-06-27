#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1245. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25339);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/05/17 23:41:27 $");

  script_cve_id("CVE-2005-4816");
  script_xref(name:"DSA", value:"1245");

  script_name(english:"Debian DSA-1245-1 : proftpd - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Martin Loewer discovered that the proftpd FTP daemon is vulnerable to
denial of service if the addon module for Radius authentication is
enabled."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=404751"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1245"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the proftpd package.

For the stable distribution (sarge) this problem has been fixed in
version 1.2.10-15sarge4.

For the upcoming stable distribution (etch) this problem has been
fixed in version 1.2.10+1.3.0rc5-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"proftpd", reference:"1.2.10-15sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"proftpd-common", reference:"1.2.10-15sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"proftpd-doc", reference:"1.2.10-15sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"proftpd-ldap", reference:"1.2.10-15sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"proftpd-mysql", reference:"1.2.10-15sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"proftpd-pgsql", reference:"1.2.10-15sarge4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
