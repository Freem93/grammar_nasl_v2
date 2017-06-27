#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-200. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15037);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/17 23:54:24 $");

  script_cve_id("CVE-2002-1318");
  script_xref(name:"DSA", value:"200");

  script_name(english:"Debian DSA-200-1 : samba - remote exploit");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Steve Langasek found an exploitable bug in the password handling code
in samba: when converting from DOS code-page to little endian UCS2
unicode a buffer length was not checked and a buffer could be
overflowed. There is no known exploit for this, but an upgrade is
strongly recommended."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-200"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"This problem has been fixed in version 2.2.3a-12 of the Debian samba
packages and upstream version 2.2.7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba 2.2.2 - 2.2.6 nttrans Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/11/22");
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
if (deb_check(release:"3.0", prefix:"libpam-smbpass", reference:"2.2.3a-12")) flag++;
if (deb_check(release:"3.0", prefix:"libsmbclient", reference:"2.2.3a-12")) flag++;
if (deb_check(release:"3.0", prefix:"libsmbclient-dev", reference:"2.2.3a-12")) flag++;
if (deb_check(release:"3.0", prefix:"samba", reference:"2.2.3a-12")) flag++;
if (deb_check(release:"3.0", prefix:"samba-common", reference:"2.2.3a-12")) flag++;
if (deb_check(release:"3.0", prefix:"samba-doc", reference:"2.2.3a-12")) flag++;
if (deb_check(release:"3.0", prefix:"smbclient", reference:"2.2.3a-12")) flag++;
if (deb_check(release:"3.0", prefix:"smbfs", reference:"2.2.3a-12")) flag++;
if (deb_check(release:"3.0", prefix:"swat", reference:"2.2.3a-12")) flag++;
if (deb_check(release:"3.0", prefix:"winbind", reference:"2.2.3a-12")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
