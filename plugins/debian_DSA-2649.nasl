#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2649. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65585);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2013-1427");
  script_osvdb_id(91462);
  script_xref(name:"DSA", value:"2649");

  script_name(english:"Debian DSA-2649-1 : lighttpd - fixed socket name in world-writable directory");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Stefan Buhler discovered that the Debian specific configuration file
for lighttpd webserver FastCGI PHP support used a fixed socket name in
the world-writable /tmp directory. A symlink attack or a race
condition could be exploited by a malicious user on the same machine
to take over the PHP control socket and for example force the
webserver to use a different PHP version.

As the fix is in a configuration file lying in /etc, the update won't
be enforced if the file has been modified by the administrator. In
that case, care should be taken to manually apply the fix."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/lighttpd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2649"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the lighttpd packages.

For the stable distribution (squeeze), this problem has been fixed in
version 1.4.28-2+squeeze1.3."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"lighttpd", reference:"1.4.28-2+squeeze1.3")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-doc", reference:"1.4.28-2+squeeze1.3")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-mod-cml", reference:"1.4.28-2+squeeze1.3")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-mod-magnet", reference:"1.4.28-2+squeeze1.3")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-mod-mysql-vhost", reference:"1.4.28-2+squeeze1.3")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-mod-trigger-b4-dl", reference:"1.4.28-2+squeeze1.3")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-mod-webdav", reference:"1.4.28-2+squeeze1.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
