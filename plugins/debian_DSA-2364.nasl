#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2364. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57504);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:31:56 $");

  script_cve_id("CVE-2011-4613");
  script_bugtraq_id(51082);
  script_xref(name:"DSA", value:"2364");

  script_name(english:"Debian DSA-2364-1 : xorg - incorrect permission check");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Debian X wrapper enforces that the X server can only be started
from a console. 'vladz' discovered that this wrapper could be
bypassed.

The oldstable distribution (lenny) is not affected."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=652249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/xorg"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2364"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xorg packages.

For the stable distribution (squeeze), this problem has been fixed in
version 7.5+8+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xorg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libglu1-xorg", reference:"7.5+8+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libglu1-xorg-dev", reference:"7.5+8+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"x11-common", reference:"7.5+8+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"xbase-clients", reference:"7.5+8+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"xlibmesa-gl", reference:"7.5+8+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"xlibmesa-gl-dev", reference:"7.5+8+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"xlibmesa-glu", reference:"7.5+8+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"xorg", reference:"7.5+8+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"xorg-dev", reference:"7.5+8+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-xorg", reference:"7.5+8+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-xorg-input-all", reference:"7.5+8+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-xorg-video-all", reference:"7.5+8+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"xutils", reference:"7.5+8+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
