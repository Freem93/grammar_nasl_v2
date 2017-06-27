#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3642. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92955);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/08/15 14:21:39 $");

  script_cve_id("CVE-2016-1000212");
  script_xref(name:"DSA", value:"3642");

  script_name(english:"Debian DSA-3642-1 : lighttpd - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Dominic Scheirlinck and Scott Geary of Vend reported insecure behavior
in the lighttpd web server. Lighttpd assigned Proxy header values from
client requests to internal HTTP_PROXY environment variables, allowing
remote attackers to carry out Man in the Middle (MITM) attacks or
initiate connections to arbitrary hosts."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=832571"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/lighttpd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3642"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the lighttpd packages.

For the stable distribution (jessie), this problem has been fixed in
version 1.4.35-4+deb8u1."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"lighttpd", reference:"1.4.35-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lighttpd-doc", reference:"1.4.35-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lighttpd-mod-cml", reference:"1.4.35-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lighttpd-mod-magnet", reference:"1.4.35-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lighttpd-mod-mysql-vhost", reference:"1.4.35-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lighttpd-mod-trigger-b4-dl", reference:"1.4.35-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lighttpd-mod-webdav", reference:"1.4.35-4+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
