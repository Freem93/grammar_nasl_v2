#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3812. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97801);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/03/30 13:31:42 $");

  script_cve_id("CVE-2017-6903");
  script_osvdb_id(153774);
  script_xref(name:"DSA", value:"3812");

  script_name(english:"Debian DSA-3812-1 : ioquake3 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that ioquake3, a modified version of the ioQuake3
game engine performs insufficent restrictions on automatically
downloaded content (pk3 files or game code), which allows malicious
game servers to modify configuration settings including driver
settings."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/ioquake3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2017/dsa-3812"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ioquake3 packages.

For the stable distribution (jessie), this problem has been fixed in
version 1.36+u20140802+gca9eebb-2+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ioquake3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/20");
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
if (deb_check(release:"8.0", prefix:"ioquake3", reference:"1.36+u20140802+gca9eebb-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ioquake3-dbg", reference:"1.36+u20140802+gca9eebb-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ioquake3-server", reference:"1.36+u20140802+gca9eebb-2+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
