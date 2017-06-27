#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3166. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81446);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/02/24 14:41:20 $");

  script_cve_id("CVE-2015-0247", "CVE-2015-1572");
  script_bugtraq_id(72520);
  script_xref(name:"DSA", value:"3166");

  script_name(english:"Debian DSA-3166-1 : e2fsprogs - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jose Duart of the Google Security Team discovered a buffer overflow in
e2fsprogs, a set of utilities for the ext2, ext3, and ext4 file
systems. This issue can possibly lead to arbitrary code execution if a
malicious device is plugged in, the system is configured to
automatically mount it, and the mounting process chooses to run fsck
on the device's malicious filesystem.

  - CVE-2015-0247
    Buffer overflow in the ext2/ext3/ext4 file system
    open/close routines.

  - CVE-2015-1572
    Incomplete fix for CVE-2015-0247."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=778948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-0247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-0247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/e2fsprogs"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3166"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the e2fsprogs packages.

For the stable distribution (wheezy), these problems have been fixed
in version 1.42.5-1.1+deb7u1.

For the upcoming stable (jessie) and unstable (sid) distributions,
these problems will be fixed soon."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:e2fsprogs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/24");
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
if (deb_check(release:"7.0", prefix:"comerr-dev", reference:"1.42.5-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"e2fsck-static", reference:"1.42.5-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"e2fslibs", reference:"1.42.5-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"e2fslibs-dbg", reference:"1.42.5-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"e2fslibs-dev", reference:"1.42.5-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"e2fsprogs", reference:"1.42.5-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"e2fsprogs-dbg", reference:"1.42.5-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libcomerr2", reference:"1.42.5-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libcomerr2-dbg", reference:"1.42.5-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libss2", reference:"1.42.5-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libss2-dbg", reference:"1.42.5-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ss-dev", reference:"1.42.5-1.1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
