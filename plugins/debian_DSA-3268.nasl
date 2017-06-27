#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3268. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83785);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2015/11/05 16:11:32 $");

  script_cve_id("CVE-2015-3202");
  script_bugtraq_id(74765);
  script_osvdb_id(122415);
  script_xref(name:"DSA", value:"3268");

  script_name(english:"Debian DSA-3268-1 : ntfs-3g - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tavis Ormandy discovered that NTFS-3G, a read-write NTFS driver for
FUSE, does not scrub the environment before executing mount or umount
with elevated privileges. A local user can take advantage of this flaw
to overwrite arbitrary files and gain elevated privileges by accessing
debugging features via the environment that would not normally be safe
for unprivileged users."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=786475"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/ntfs-3g"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/ntfs-3g"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3268"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ntfs-3g packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 1:2012.1.15AR.5-2.1+deb7u1. Note that this issue does not
affect the binary packages distributed in Debian in wheezy as ntfs-3g
does not use the embedded fuse-lite library.

For the stable distribution (jessie), this problem has been fixed in
version 1:2014.2.15AR.2-1+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntfs-3g");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/26");
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
if (deb_check(release:"7.0", prefix:"ntfs-3g", reference:"1:2012.1.15AR.5-2.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ntfs-3g-dbg", reference:"1:2012.1.15AR.5-2.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ntfs-3g-dev", reference:"1:2012.1.15AR.5-2.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ntfsprogs", reference:"1:2012.1.15AR.5-2.1+deb7u1")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-3g", reference:"1:2014.2.15AR.2-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-3g-dbg", reference:"1:2014.2.15AR.2-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ntfs-3g-dev", reference:"1:2014.2.15AR.2-1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
