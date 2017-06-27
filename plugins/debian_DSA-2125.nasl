#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2125. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50696);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/09/28 23:36:00 $");

  script_cve_id("CVE-2010-3864");
  script_bugtraq_id(44884);
  script_xref(name:"DSA", value:"2125");

  script_name(english:"Debian DSA-2125-1 : openssl - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw has been found in the OpenSSL TLS server extension code parsing
which on affected servers can be exploited in a buffer overrun attack.
This allows an attacker to cause an application crash or potentially
to execute arbitrary code.

However, not all OpenSSL based SSL/TLS servers are vulnerable: a
server is vulnerable if it is multi-threaded and uses OpenSSL's
internal caching mechanism. In particular the Apache HTTP server
(which never uses OpenSSL internal caching) and Stunnel (which
includes its own workaround) are NOT affected."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=603709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2125"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssl packages.

This upgrade fixes this issue. After the upgrade, any services using
the openssl libraries need to be restarted. The checkrestart script
from the debian-goodies package or lsof can help to find out which
services need to be restarted.

A note to users of the tor packages from the Debian backports or
Debian volatile: this openssl update causes problems with some
versions of tor. You need to update to tor 0.2.1.26-4~bpo50+1 or
0.2.1.26-1~lennyvolatile2, respectively. The tor package version
0.2.0.35-1~lenny2 from Debian stable is not affected by these
problems.

For the stable distribution (lenny), the problem has been fixed in
openssl version 0.9.8g-15+lenny9."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"libssl-dev", reference:"0.9.8g-15+lenny9")) flag++;
if (deb_check(release:"5.0", prefix:"libssl0.9.8", reference:"0.9.8g-15+lenny9")) flag++;
if (deb_check(release:"5.0", prefix:"libssl0.9.8-dbg", reference:"0.9.8g-15+lenny9")) flag++;
if (deb_check(release:"5.0", prefix:"openssl", reference:"0.9.8g-15+lenny9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
