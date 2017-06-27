#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3095. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79882);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/05 16:01:11 $");

  script_cve_id("CVE-2014-8091", "CVE-2014-8092", "CVE-2014-8093", "CVE-2014-8094", "CVE-2014-8095", "CVE-2014-8096", "CVE-2014-8097", "CVE-2014-8098", "CVE-2014-8099", "CVE-2014-8100", "CVE-2014-8101", "CVE-2014-8102");
  script_bugtraq_id(71595, 71596, 71597, 71598, 71599, 71600, 71601, 71602, 71604, 71605, 71606, 71608);
  script_osvdb_id(115603, 115604, 115605, 115606, 115607, 115608, 115609, 115610, 115611, 115612, 115613, 115615);
  script_xref(name:"DSA", value:"3095");

  script_name(english:"Debian DSA-3095-1 : xorg-server - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ilja van Sprundel of IOActive discovered several security issues in
the X.org X server, which may lead to privilege escalation or denial
of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/xorg-server"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-3095"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xorg-server packages.

For the stable distribution (wheezy), these problems have been fixed
in version 1.12.4-6+deb7u5.

For the upcoming stable distribution (jessie), these problems will be
fixed soon."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xorg-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
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
if (deb_check(release:"7.0", prefix:"xdmx", reference:"1.12.4-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"xdmx-tools", reference:"1.12.4-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"xnest", reference:"1.12.4-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"xserver-common", reference:"1.12.4-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"xserver-xephyr", reference:"1.12.4-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"xserver-xfbdev", reference:"1.12.4-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"xserver-xorg-core", reference:"1.12.4-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"xserver-xorg-core-dbg", reference:"1.12.4-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"xserver-xorg-core-udeb", reference:"1.12.4-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"xserver-xorg-dev", reference:"1.12.4-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"xvfb", reference:"1.12.4-6+deb7u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
