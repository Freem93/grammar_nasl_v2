#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1955. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44820);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:49:56 $");

  script_cve_id("CVE-2009-0365");
  script_bugtraq_id(33966);
  script_osvdb_id(53653);
  script_xref(name:"DSA", value:"1955");

  script_name(english:"Debian DSA-1955-1 : network-manager/network-manager-applet - information disclosure");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that network-manager-applet, a network management
framework, lacks some dbus restriction rules, which allows local users
to obtain sensitive information.

If you have locally modified the /etc/dbus-1/system.d/nm-applet.conf
file, then please make sure that you merge the changes from this fix
when asked during upgrade."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=519801"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1955"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the network-manager and network-manager-applet packages
accordingly.

For the oldstable distribution (etch), this problem has been fixed in
version 0.6.4-6+etch1 of network-manager.

For the stable distribution (lenny), this problem has been fixed in
version 0.6.6-4+lenny1 of network-manager-applet."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:network-manager-applet");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libnm-glib-dev", reference:"0.6.4-6+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libnm-glib0", reference:"0.6.4-6+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libnm-util-dev", reference:"0.6.4-6+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libnm-util0", reference:"0.6.4-6+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"network-manager", reference:"0.6.4-6+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"network-manager-dev", reference:"0.6.4-6+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"network-manager-gnome", reference:"0.6.4-6+etch1")) flag++;
if (deb_check(release:"5.0", prefix:"network-manager-gnome", reference:"0.6.6-4+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
