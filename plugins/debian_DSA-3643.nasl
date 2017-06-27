#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3643. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92764);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/06 20:25:09 $");

  script_cve_id("CVE-2016-6232");
  script_osvdb_id(141593);
  script_xref(name:"DSA", value:"3643");

  script_name(english:"Debian DSA-3643-1 : kde4libs - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Andreas Cord-Landwehr discovered that kde4libs, the core libraries for
all KDE 4 applications, do not properly handle the extraction of
archives with '../' in the file paths. A remote attacker can take
advantage of this flaw to overwrite files outside of the extraction
folder, if a user is tricked into extracting a specially crafted
archive."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=832620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/kde4libs"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3643"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kde4libs packages.

For the stable distribution (jessie), this problem has been fixed in
version 4:4.14.2-5+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kde4libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/08");
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
if (deb_check(release:"8.0", prefix:"kdelibs-bin", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kdelibs5-data", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kdelibs5-dbg", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kdelibs5-dev", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kdelibs5-plugins", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kdoctools", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkcmutils4", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkde3support4", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkdeclarative5", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkdecore5", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkdesu5", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkdeui5", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkdewebkit5", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkdnssd4", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkemoticons4", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkfile4", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkhtml5", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkidletime4", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkimproxy4", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkio5", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkjsapi4", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkjsembed4", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkmediaplayer4", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libknewstuff2-4", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libknewstuff3-4", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libknotifyconfig4", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkntlm4", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkparts4", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkprintutils4", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkpty4", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkrosscore4", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkrossui4", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libktexteditor4", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkunitconversion4", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkutils4", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libnepomuk4", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libnepomukquery4a", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libnepomukutils4", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libplasma3", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsolid4", reference:"4:4.14.2-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libthreadweaver4", reference:"4:4.14.2-5+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
