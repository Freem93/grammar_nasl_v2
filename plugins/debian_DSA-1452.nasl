#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1452. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29861);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/05/17 23:45:45 $");

  script_cve_id("CVE-2007-5300");
  script_osvdb_id(41636);
  script_xref(name:"DSA", value:"1452");

  script_name(english:"Debian DSA-1452-1 : wzdftpd - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"'k1tk4t' discovered that wzdftpd, a portable, modular, small and
efficient ftp server, did not correctly handle the receipt of long
usernames. This could allow remote users to cause the daemon to exit."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=446192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1452"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wzdftpd package.

For the old stable distribution (sarge), this problem has been fixed
in version 0.5.2-1.1sarge3.

For the stable distribution (etch), this problem has been fixed in
version 0.8.1-2etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(119,189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wzdftpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"wzdftpd", reference:"0.5.2-1.1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"wzdftpd-back-mysql", reference:"0.5.2-1.1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"wzdftpd-dev", reference:"0.5.2-1.1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"wzdftpd-mod-perl", reference:"0.5.2-1.1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"wzdftpd-mod-tcl", reference:"0.5.2-1.1sarge3")) flag++;
if (deb_check(release:"4.0", prefix:"wzdftpd", reference:"0.8.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"wzdftpd-back-mysql", reference:"0.8.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"wzdftpd-back-pgsql", reference:"0.8.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"wzdftpd-dev", reference:"0.8.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"wzdftpd-mod-avahi", reference:"0.8.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"wzdftpd-mod-perl", reference:"0.8.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"wzdftpd-mod-tcl", reference:"0.8.1-2etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
