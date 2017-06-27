#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3266. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83775);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2015/11/05 16:11:32 $");

  script_cve_id("CVE-2015-3202");
  script_osvdb_id(122415);
  script_xref(name:"DSA", value:"3266");

  script_name(english:"Debian DSA-3266-1 : fuse - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tavis Ormandy discovered that FUSE, a Filesystem in USErspace, does
not scrub the environment before executing mount or umount with
elevated privileges. A local user can take advantage of this flaw to
overwrite arbitrary files and gain elevated privileges by accessing
debugging features via the environment that would not normally be safe
for unprivileged users."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=786439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/fuse"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/fuse"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3266"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the fuse packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 2.9.0-2+deb7u2.

For the stable distribution (jessie), this problem has been fixed in
version 2.9.3-15+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/22");
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
if (deb_check(release:"7.0", prefix:"fuse", reference:"2.9.0-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"fuse-dbg", reference:"2.9.0-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"fuse-utils", reference:"2.9.0-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libfuse-dev", reference:"2.9.0-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libfuse2", reference:"2.9.0-2+deb7u2")) flag++;
if (deb_check(release:"8.0", prefix:"fuse", reference:"2.9.3-15+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fuse-dbg", reference:"2.9.3-15+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libfuse-dev", reference:"2.9.3-15+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libfuse2", reference:"2.9.3-15+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
