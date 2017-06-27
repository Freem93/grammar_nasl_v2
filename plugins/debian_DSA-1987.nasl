#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1987. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44851);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/04/03 11:06:11 $");

  script_cve_id("CVE-2010-0295");
  script_bugtraq_id(38036);
  script_osvdb_id(62068);
  script_xref(name:"DSA", value:"1987");

  script_name(english:"Debian DSA-1987-1 : lighttpd - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Li Ming discovered that lighttpd, a small and fast webserver with
minimal memory footprint, is vulnerable to a denial of service attack
due to bad memory handling. Slowly sending very small chunks of
request data causes lighttpd to allocate new buffers for each read
instead of appending to old ones. An attacker can abuse this behaviour
to cause denial of service conditions due to memory exhaustion."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-1987"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the lighttpd packages.

For the oldstable distribution (etch), this problem has been fixed in
version 1.4.13-4etch12.

For the stable distribution (lenny), this problem has been fixed in
version 1.4.19-5+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"lighttpd", reference:"1.4.13-4etch12")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-doc", reference:"1.4.13-4etch12")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-mod-cml", reference:"1.4.13-4etch12")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-mod-magnet", reference:"1.4.13-4etch12")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-mod-mysql-vhost", reference:"1.4.13-4etch12")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-mod-trigger-b4-dl", reference:"1.4.13-4etch12")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-mod-webdav", reference:"1.4.13-4etch12")) flag++;
if (deb_check(release:"5.0", prefix:"lighttpd", reference:"1.4.19-5+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"lighttpd-doc", reference:"1.4.19-5+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"lighttpd-mod-cml", reference:"1.4.19-5+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"lighttpd-mod-magnet", reference:"1.4.19-5+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"lighttpd-mod-mysql-vhost", reference:"1.4.19-5+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"lighttpd-mod-trigger-b4-dl", reference:"1.4.19-5+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"lighttpd-mod-webdav", reference:"1.4.19-5+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
