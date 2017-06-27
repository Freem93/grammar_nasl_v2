#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3274. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83889);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/05/05 16:01:12 $");

  script_cve_id("CVE-2015-3456");
  script_bugtraq_id(74640);
  script_osvdb_id(122072);
  script_xref(name:"DSA", value:"3274");

  script_name(english:"Debian DSA-3274-1 : virtualbox - security update (Venom)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jason Geffner discovered a buffer overflow in the emulated floppy disk
drive, resulting in potential privilege escalation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/virtualbox"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/virtualbox"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3274"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the virtualbox packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 4.1.18-dfsg-2+deb7u5.

For the stable distribution (jessie), this problem has been fixed in
version 4.3.18-dfsg-3+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:virtualbox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/28");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"virtualbox", reference:"4.1.18-dfsg-2+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-dbg", reference:"4.1.18-dfsg-2+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-dkms", reference:"4.1.18-dfsg-2+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-fuse", reference:"4.1.18-dfsg-2+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-guest-dkms", reference:"4.1.18-dfsg-2+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-guest-source", reference:"4.1.18-dfsg-2+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-guest-utils", reference:"4.1.18-dfsg-2+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-guest-x11", reference:"4.1.18-dfsg-2+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-ose", reference:"4.1.18-dfsg-2+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-ose-dbg", reference:"4.1.18-dfsg-2+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-ose-dkms", reference:"4.1.18-dfsg-2+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-ose-fuse", reference:"4.1.18-dfsg-2+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-ose-guest-dkms", reference:"4.1.18-dfsg-2+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-ose-guest-source", reference:"4.1.18-dfsg-2+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-ose-guest-utils", reference:"4.1.18-dfsg-2+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-ose-guest-x11", reference:"4.1.18-dfsg-2+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-ose-qt", reference:"4.1.18-dfsg-2+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-ose-source", reference:"4.1.18-dfsg-2+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-qt", reference:"4.1.18-dfsg-2+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"virtualbox-source", reference:"4.1.18-dfsg-2+deb7u5")) flag++;
if (deb_check(release:"8.0", prefix:"virtualbox", reference:"4.3.18-dfsg-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtualbox-dbg", reference:"4.3.18-dfsg-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtualbox-dkms", reference:"4.3.18-dfsg-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtualbox-guest-dkms", reference:"4.3.18-dfsg-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtualbox-guest-source", reference:"4.3.18-dfsg-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtualbox-guest-utils", reference:"4.3.18-dfsg-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtualbox-guest-x11", reference:"4.3.18-dfsg-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtualbox-qt", reference:"4.3.18-dfsg-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"virtualbox-source", reference:"4.3.18-dfsg-3+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
