#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-098. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14935);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/10/05 13:32:57 $");

  script_cve_id("CVE-2001-0927", "CVE-2001-0928");
  script_xref(name:"DSA", value:"098");

  script_name(english:"Debian DSA-098-1 : libgtop - format string vulnerability and buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two different problems were found in libgtop-daemon :

  - The laboratory intexxia found a format string problem in
    the logging code from libgtop_daemon. There were two
    logging functions which are called when authorizing a
    client which could be exploited by a remote user.
  - Flavio Veloso found a buffer overflow in the function
    that authorizes clients.

Since libgtop_daemon runs as user nobody, both bugs could be used to
gain access as the nobody user to a system running libgtop_daemon.


Both problems have been fixed in version 1.0.6-1.1 and we recommend
you upgrade your libgtop-daemon package immediately."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-098"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected libgtop package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgtop");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"libgtop-daemon", reference:"1.0.6-1.1")) flag++;
if (deb_check(release:"2.2", prefix:"libgtop-dev", reference:"1.0.6-1.1")) flag++;
if (deb_check(release:"2.2", prefix:"libgtop1", reference:"1.0.6-1.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
