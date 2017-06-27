#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3556. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90688);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2016-3074");
  script_osvdb_id(137447);
  script_xref(name:"DSA", value:"3556");

  script_name(english:"Debian DSA-3556-1 : libgd2 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Hans Jerry Illikainen discovered that libgd2, a library for
programmatic graphics creation and manipulation, suffers of a
signedness vulnerability which may result in a heap overflow when
processing specially crafted compressed gd2 data. A remote attacker
can take advantage of this flaw to cause an application using the
libgd2 library to crash, or potentially, to execute arbitrary code
with the privileges of the user running the application."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=822242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libgd2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libgd2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3556"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libgd2 packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 2.0.36~rc1~dfsg-6.1+deb7u2.

For the stable distribution (jessie), this problem has been fixed in
version 2.1.0-5+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgd2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/25");
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
if (deb_check(release:"7.0", prefix:"libgd-tools", reference:"2.0.36~rc1~dfsg-6.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libgd2-noxpm", reference:"2.0.36~rc1~dfsg-6.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libgd2-noxpm-dev", reference:"2.0.36~rc1~dfsg-6.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libgd2-xpm", reference:"2.0.36~rc1~dfsg-6.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libgd2-xpm-dev", reference:"2.0.36~rc1~dfsg-6.1+deb7u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgd-dbg", reference:"2.1.0-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgd-dev", reference:"2.1.0-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgd-tools", reference:"2.1.0-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgd2-noxpm-dev", reference:"2.1.0-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgd2-xpm-dev", reference:"2.1.0-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgd3", reference:"2.1.0-5+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
