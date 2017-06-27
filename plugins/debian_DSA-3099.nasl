#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3099. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79886);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/07/23 15:02:09 $");

  script_cve_id("CVE-2014-7824");
  script_bugtraq_id(71012);
  script_osvdb_id(111642);
  script_xref(name:"DSA", value:"3099");

  script_name(english:"Debian DSA-3099-1 : dbus - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Simon McVittie discovered that the fix for CVE-2014-3636 was
incorrect, as it did not fully address the underlying
denial-of-service vector. This update starts the D-Bus daemon as root
initially, so that it can properly raise its file descriptor count.

In addition, this update reverts the auth_timeout change in the
previous security update to its old value because the new value causes
boot failures on some systems. See the README.Debian file for details
how to harden the D-Bus daemon against malicious local users."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3636"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/dbus"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-3099"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the dbus packages.

For the stable distribution (wheezy), these problem have been fixed in
version 1.6.8-1+deb7u5.

For the upcoming stable distribution (jessie) and the unstable
distribution (sid), these problem have been fixed in version 1.8.10-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dbus");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"dbus", reference:"1.6.8-1+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"dbus-1-dbg", reference:"1.6.8-1+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"dbus-1-doc", reference:"1.6.8-1+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"dbus-x11", reference:"1.6.8-1+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libdbus-1-3", reference:"1.6.8-1+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libdbus-1-dev", reference:"1.6.8-1+deb7u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
