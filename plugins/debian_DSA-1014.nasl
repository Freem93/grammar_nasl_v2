#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1014. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22556);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/17 23:36:51 $");

  script_cve_id("CVE-2004-2043");
  script_bugtraq_id(10446);
  script_osvdb_id(6408);
  script_xref(name:"DSA", value:"1014");

  script_name(english:"Debian DSA-1014-1 : firebird2 - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Aviram Jenik and Damyan Ivanov discovered a buffer overflow in
firebird2, an RDBMS based on InterBase 6.0 code, that allows remote
attackers to crash."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=357580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1014"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the firebird2 packages.

The old stable distribution (woody) does not contain firebird2
packages.

For the stable distribution (sarge) this problem has been fixed in
version 1.5.1-4sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firebird2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/06/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"firebird2-classic-server", reference:"1.5.1-4sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"firebird2-dev", reference:"1.5.1-4sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"firebird2-examples", reference:"1.5.1-4sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"firebird2-server-common", reference:"1.5.1-4sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"firebird2-super-server", reference:"1.5.1-4sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"firebird2-utils-classic", reference:"1.5.1-4sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"firebird2-utils-super", reference:"1.5.1-4sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libfirebird2-classic", reference:"1.5.1-4sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libfirebird2-super", reference:"1.5.1-4sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
