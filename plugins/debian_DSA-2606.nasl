#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2606. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63512);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:37:39 $");

  script_cve_id("CVE-2012-6095");
  script_bugtraq_id(57172);
  script_osvdb_id(89051);
  script_xref(name:"DSA", value:"2606");

  script_name(english:"Debian DSA-2606-1 : proftpd-dfsg - symlink race");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It has been discovered that in ProFTPd, an FTP server, an attacker on
the same physical host as the server may be able to perform a symlink
attack allowing to elevate privileges in some configurations."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=697524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/proftpd-dfsg"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2606"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the proftpd-dfsg packages.

For the stable distribution (squeeze), this problem has been fixed in
version 1.3.3a-6squeeze6."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-dfsg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"proftpd-basic", reference:"1.3.3a-6squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"proftpd-dev", reference:"1.3.3a-6squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"proftpd-doc", reference:"1.3.3a-6squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"proftpd-mod-ldap", reference:"1.3.3a-6squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"proftpd-mod-mysql", reference:"1.3.3a-6squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"proftpd-mod-odbc", reference:"1.3.3a-6squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"proftpd-mod-pgsql", reference:"1.3.3a-6squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"proftpd-mod-sqlite", reference:"1.3.3a-6squeeze6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
