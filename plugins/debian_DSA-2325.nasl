#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2325. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56586);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/16 15:31:56 $");

  script_cve_id("CVE-2011-4062");
  script_bugtraq_id(49862);
  script_osvdb_id(75788);
  script_xref(name:"DSA", value:"2325");

  script_name(english:"Debian DSA-2325-1 : kfreebsd-8 - privilege escalation/denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Buffer overflow in the 'Linux emulation' support in FreeBSD kernel
allows local users to cause a denial of service (panic) and possibly
execute arbitrary code by calling the bind system call with a long
path for a UNIX-domain socket, which is not properly handled when the
address is used by other unspecified system calls."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/kfreebsd-8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2325"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kfreebsd-8 packages.

For the stable distribution (squeeze), this problem has been fixed in
version 8.1+dfsg-8+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kfreebsd-8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"kfreebsd-headers-8-486", reference:"8.1+dfsg-8+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-headers-8-686", reference:"8.1+dfsg-8+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-headers-8-686-smp", reference:"8.1+dfsg-8+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-headers-8-amd64", reference:"8.1+dfsg-8+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-headers-8.1-1", reference:"8.1+dfsg-8+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-headers-8.1-1-486", reference:"8.1+dfsg-8+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-headers-8.1-1-686", reference:"8.1+dfsg-8+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-headers-8.1-1-686-smp", reference:"8.1+dfsg-8+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-headers-8.1-1-amd64", reference:"8.1+dfsg-8+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-image-8-486", reference:"8.1+dfsg-8+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-image-8-686", reference:"8.1+dfsg-8+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-image-8-686-smp", reference:"8.1+dfsg-8+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-image-8-amd64", reference:"8.1+dfsg-8+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-image-8.1-1-486", reference:"8.1+dfsg-8+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-image-8.1-1-686", reference:"8.1+dfsg-8+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-image-8.1-1-686-smp", reference:"8.1+dfsg-8+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-image-8.1-1-amd64", reference:"8.1+dfsg-8+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-source-8.1", reference:"8.1+dfsg-8+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
