#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2822. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71527);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:43:10 $");

  script_cve_id("CVE-2013-6424");
  script_bugtraq_id(64127);
  script_osvdb_id(100613);
  script_xref(name:"DSA", value:"2822");

  script_name(english:"Debian DSA-2822-1 : xorg-server - integer underflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Bryan Quigley discovered an integer underflow in the Xorg X server
which could lead to denial of service or the execution of arbitrary
code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/xorg-server"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/xorg-server"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2822"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xorg-server packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 1.7.7-18.

For the stable distribution (wheezy), this problem has been fixed in
version 1.12.4-6+deb7u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xorg-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"xdmx", reference:"1.7.7-18")) flag++;
if (deb_check(release:"6.0", prefix:"xdmx-tools", reference:"1.7.7-18")) flag++;
if (deb_check(release:"6.0", prefix:"xnest", reference:"1.7.7-18")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-common", reference:"1.7.7-18")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-xephyr", reference:"1.7.7-18")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-xfbdev", reference:"1.7.7-18")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-xorg-core", reference:"1.7.7-18")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-xorg-core-dbg", reference:"1.7.7-18")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-xorg-core-udeb", reference:"1.7.7-18")) flag++;
if (deb_check(release:"6.0", prefix:"xserver-xorg-dev", reference:"1.7.7-18")) flag++;
if (deb_check(release:"6.0", prefix:"xvfb", reference:"1.7.7-18")) flag++;
if (deb_check(release:"7.0", prefix:"xdmx", reference:"1.12.4-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"xdmx-tools", reference:"1.12.4-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"xnest", reference:"1.12.4-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"xserver-common", reference:"1.12.4-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"xserver-xephyr", reference:"1.12.4-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"xserver-xfbdev", reference:"1.12.4-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"xserver-xorg-core", reference:"1.12.4-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"xserver-xorg-core-dbg", reference:"1.12.4-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"xserver-xorg-core-udeb", reference:"1.12.4-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"xserver-xorg-dev", reference:"1.12.4-6+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"xvfb", reference:"1.12.4-6+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
