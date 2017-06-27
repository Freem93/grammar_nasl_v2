#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1658. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34478);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/05/17 23:49:55 $");

  script_cve_id("CVE-2008-3834");
  script_xref(name:"DSA", value:"1658");

  script_name(english:"Debian DSA-1658-1 : dbus - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Colin Walters discovered that the dbus_signature_validate function in
dbus, a simple interprocess messaging system, is prone to a denial of
service attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=501443"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1658"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the dbus package.

For the stable distribution (etch), this problem has been fixed in
version 1.0.2-1+etch2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dbus");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/24");
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
if (deb_check(release:"4.0", prefix:"dbus", reference:"1.0.2-1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"dbus-1-doc", reference:"1.0.2-1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"dbus-1-utils", reference:"1.0.2-1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libdbus-1-3", reference:"1.0.2-1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libdbus-1-dev", reference:"1.0.2-1+etch2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
