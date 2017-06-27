#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3215. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82623);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/05 13:44:21 $");

  script_cve_id("CVE-2014-2497", "CVE-2014-9709");
  script_bugtraq_id(66233, 73306);
  script_xref(name:"DSA", value:"3215");

  script_name(english:"Debian DSA-3215-1 : libgd2 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in libgd2, a graphics library
:

  - CVE-2014-2497
    The gdImageCreateFromXpm() function would try to
    dereference a NULL pointer when reading an XPM file with
    a special color table. This could allow remote attackers
    to cause a denial of service (crash) via crafted XPM
    files.

  - CVE-2014-9709
    Importing an invalid GIF file using the
    gdImageCreateFromGif() function would cause a read
    buffer overflow that could allow remote attackers to
    cause a denial of service (crash) via crafted GIF files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=744719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-2497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libgd2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3215"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libgd2 packages.

For the stable distribution (wheezy), these problems have been fixed
in version 2.0.36~rc1~dfsg-6.1+deb7u1.

For the upcoming stable distribution (jessie), these problems have
been fixed in version 2.1.0-5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgd2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libgd-tools", reference:"2.0.36~rc1~dfsg-6.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgd2-noxpm", reference:"2.0.36~rc1~dfsg-6.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgd2-noxpm-dev", reference:"2.0.36~rc1~dfsg-6.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgd2-xpm", reference:"2.0.36~rc1~dfsg-6.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgd2-xpm-dev", reference:"2.0.36~rc1~dfsg-6.1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
