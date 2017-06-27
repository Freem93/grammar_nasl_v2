#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3026. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77716);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/06/03 14:00:06 $");

  script_cve_id("CVE-2014-3635", "CVE-2014-3636", "CVE-2014-3637", "CVE-2014-3638", "CVE-2014-3639");
  script_bugtraq_id(69829, 69831, 69832, 69833, 69834);
  script_osvdb_id(111638, 111639, 111640, 111641, 111642);
  script_xref(name:"DSA", value:"3026");

  script_name(english:"Debian DSA-3026-1 : dbus - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Alban Crequy and Simon McVittie discovered several vulnerabilities in
the D-Bus message daemon.

  - CVE-2014-3635
    On 64-bit platforms, file descriptor passing could be
    abused by local users to cause heap corruption in
    dbus-daemon, leading to a crash, or potentially to
    arbitrary code execution.

  - CVE-2014-3636
    A denial-of-service vulnerability in dbus-daemon allowed
    local attackers to prevent new connections to
    dbus-daemon, or disconnect existing clients, by
    exhausting descriptor limits.

  - CVE-2014-3637
    Malicious local users could create D-Bus connections to
    dbus-daemon which could not be terminated by killing the
    participating processes, resulting in a
    denial-of-service vulnerability.

  - CVE-2014-3638
    dbus-daemon suffered from a denial-of-service
    vulnerability in the code which tracks which messages
    expect a reply, allowing local attackers to reduce the
    performance of dbus-daemon.

  - CVE-2014-3639
    dbus-daemon did not properly reject malicious
    connections from local users, resulting in a
    denial-of-service vulnerability."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3636"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/dbus"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-3026"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the dbus packages.

For the stable distribution (wheezy), these problems have been fixed
in version 1.6.8-1+deb7u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dbus");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"dbus", reference:"1.6.8-1+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"dbus-1-dbg", reference:"1.6.8-1+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"dbus-1-doc", reference:"1.6.8-1+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"dbus-x11", reference:"1.6.8-1+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libdbus-1-3", reference:"1.6.8-1+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libdbus-1-dev", reference:"1.6.8-1+deb7u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
