#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3753. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96318);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/01/06 14:54:12 $");

  script_cve_id("CVE-2016-9941", "CVE-2016-9942");
  script_osvdb_id(149427, 149428);
  script_xref(name:"DSA", value:"3753");

  script_name(english:"Debian DSA-3753-1 : libvncserver - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that libvncserver, a collection of libraries used to
implement VNC/RFB clients and servers, incorrectly processed incoming
network packets. This resulted in several heap-based buffer overflows,
allowing a rogue server to either cause a DoS by crashing the client,
or potentially execute arbitrary code on the client side."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=850007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=850008"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libvncserver"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2017/dsa-3753"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libvncserver packages.

For the stable distribution (jessie), these problems have been fixed
in version 0.9.9+dfsg2-6.1+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvncserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"libvncclient0", reference:"0.9.9+dfsg2-6.1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libvncclient0-dbg", reference:"0.9.9+dfsg2-6.1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libvncserver-config", reference:"0.9.9+dfsg2-6.1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libvncserver-dev", reference:"0.9.9+dfsg2-6.1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libvncserver0", reference:"0.9.9+dfsg2-6.1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libvncserver0-dbg", reference:"0.9.9+dfsg2-6.1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"linuxvnc", reference:"0.9.9+dfsg2-6.1+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
