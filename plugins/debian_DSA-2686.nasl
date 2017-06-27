#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2686. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66570);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/21 14:37:42 $");

  script_cve_id("CVE-2013-2064");
  script_osvdb_id(93664);
  script_xref(name:"DSA", value:"2686");

  script_name(english:"Debian DSA-2686-1 : libxcb - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ilja van Sprundel of IOActive discovered several security issues in
multiple components of the X.org graphics stack and the related
libraries: Various integer overflows, sign handling errors in integer
conversions, buffer overflows, memory corruption and missing input
sanitising may lead to privilege escalation or denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/libxcb"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libxcb"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2686"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libxcb packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 1.6-1+squeeze1.

For the stable distribution (wheezy), this problem has been fixed in
version 1.8.1-2+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxcb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libxcb-composite0", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-composite0-dbg", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-composite0-dev", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-damage0", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-damage0-dbg", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-damage0-dev", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-dpms0", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-dpms0-dbg", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-dpms0-dev", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-dri2-0", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-dri2-0-dbg", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-dri2-0-dev", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-glx0", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-glx0-dbg", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-glx0-dev", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-randr0", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-randr0-dbg", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-randr0-dev", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-record0", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-record0-dbg", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-record0-dev", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-render0", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-render0-dbg", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-render0-dev", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-res0", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-res0-dbg", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-res0-dev", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-screensaver0", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-screensaver0-dbg", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-screensaver0-dev", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-shape0", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-shape0-dbg", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-shape0-dev", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-shm0", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-shm0-dbg", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-shm0-dev", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-sync0", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-sync0-dbg", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-sync0-dev", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-xevie0", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-xevie0-dbg", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-xevie0-dev", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-xf86dri0", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-xf86dri0-dbg", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-xf86dri0-dev", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-xfixes0", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-xfixes0-dbg", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-xfixes0-dev", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-xinerama0", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-xinerama0-dbg", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-xinerama0-dev", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-xprint0", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-xprint0-dbg", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-xprint0-dev", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-xtest0", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-xtest0-dbg", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-xtest0-dev", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-xv0", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-xv0-dbg", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-xv0-dev", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-xvmc0", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-xvmc0-dbg", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb-xvmc0-dev", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb1", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb1-dbg", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb1-dev", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxcb1-udeb", reference:"1.6-1+squeeze1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-composite0", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-composite0-dbg", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-composite0-dev", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-damage0", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-damage0-dbg", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-damage0-dev", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-doc", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-dpms0", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-dpms0-dbg", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-dpms0-dev", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-dri2-0", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-dri2-0-dbg", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-dri2-0-dev", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-glx0", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-glx0-dbg", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-glx0-dev", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-randr0", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-randr0-dbg", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-randr0-dev", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-record0", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-record0-dbg", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-record0-dev", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-render0", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-render0-dbg", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-render0-dev", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-res0", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-res0-dbg", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-res0-dev", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-screensaver0", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-screensaver0-dbg", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-screensaver0-dev", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-shape0", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-shape0-dbg", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-shape0-dev", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-shm0", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-shm0-dbg", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-shm0-dev", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-sync0", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-sync0-dbg", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-sync0-dev", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-xevie0", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-xevie0-dbg", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-xevie0-dev", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-xf86dri0", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-xf86dri0-dbg", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-xf86dri0-dev", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-xfixes0", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-xfixes0-dbg", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-xfixes0-dev", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-xinerama0", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-xinerama0-dbg", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-xinerama0-dev", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-xprint0", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-xprint0-dbg", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-xprint0-dev", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-xtest0", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-xtest0-dbg", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-xtest0-dev", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-xv0", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-xv0-dbg", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-xv0-dev", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-xvmc0", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-xvmc0-dbg", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb-xvmc0-dev", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb1", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb1-dbg", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb1-dev", reference:"1.8.1-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxcb1-udeb", reference:"1.8.1-2+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
