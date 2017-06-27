#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3438. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87851);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/04/28 18:33:24 $");

  script_cve_id("CVE-2015-8025");
  script_osvdb_id(129445);
  script_xref(name:"DSA", value:"3438");

  script_name(english:"Debian DSA-3438-1 : xscreensaver - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that unplugging one of the monitors in a
multi-monitor setup can cause xscreensaver to crash. Someone with
physical access to a machine could use this problem to bypass a locked
session."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=802914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/xscreensaver"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/xscreensaver"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3438"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xscreensaver packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 5.15-3+deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 5.30-1+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xscreensaver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"xscreensaver", reference:"5.15-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"xscreensaver-data", reference:"5.15-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"xscreensaver-data-extra", reference:"5.15-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"xscreensaver-gl", reference:"5.15-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"xscreensaver-gl-extra", reference:"5.15-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"xscreensaver-screensaver-bsod", reference:"5.15-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"xscreensaver-screensaver-webcollage", reference:"5.15-3+deb7u1")) flag++;
if (deb_check(release:"8.0", prefix:"xscreensaver", reference:"5.30-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xscreensaver-data", reference:"5.30-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xscreensaver-data-extra", reference:"5.30-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xscreensaver-gl", reference:"5.30-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xscreensaver-gl-extra", reference:"5.30-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xscreensaver-screensaver-bsod", reference:"5.30-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"xscreensaver-screensaver-webcollage", reference:"5.30-1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
