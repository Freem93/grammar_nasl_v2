#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2707. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66905);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/16 15:43:09 $");

  script_cve_id("CVE-2013-2168");
  script_xref(name:"DSA", value:"2707");

  script_name(english:"Debian DSA-2707-1 : dbus - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Alexandru Cornea discovered a vulnerability in libdbus caused by an
implementation bug in _dbus_printf_string_upper_bound(). This
vulnerability can be exploited by a local user to crash system
services that use libdbus, causing denial of service. Depending on the
dbus services running, it could lead to complete system crash.

The oldstable distribution (squeeze) is not affected by this problem."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/dbus"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2707"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the dbus packages.

For the stable distribution (wheezy), this problem has been fixed in
version 1.6.8-1+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dbus");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/17");
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
if (deb_check(release:"7.0", prefix:"dbus", reference:"1.6.8-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"dbus-1-dbg", reference:"1.6.8-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"dbus-1-doc", reference:"1.6.8-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"dbus-x11", reference:"1.6.8-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libdbus-1-3", reference:"1.6.8-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libdbus-1-dev", reference:"1.6.8-1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
