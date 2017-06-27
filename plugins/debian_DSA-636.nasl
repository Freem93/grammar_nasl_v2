#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-636. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16150);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/18 00:15:57 $");

  script_cve_id("CVE-2004-0968", "CVE-2004-1382");
  script_bugtraq_id(11286);
  script_osvdb_id(11040, 13933);
  script_xref(name:"DSA", value:"636");

  script_name(english:"Debian DSA-636-1 : glibc - insecure temporary files");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several insecure uses of temporary files have been discovered in
support scripts in the libc6 package which provides the c library for
a GNU/Linux system. Trustix developers found that the catchsegv script
uses temporary files insecurely. Openwall developers discovered
insecure temporary files in the glibcbug script. These scripts are
vulnerable to a symlink attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=279680"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=278278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=205600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-636"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libc6 package.

For the stable distribution (woody) these problems have been fixed in
version 2.2.5-11.8."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"glibc-doc", reference:"2.2.5-11.8")) flag++;
if (deb_check(release:"3.0", prefix:"libc6", reference:"2.2.5-11.8")) flag++;
if (deb_check(release:"3.0", prefix:"libc6-dbg", reference:"2.2.5-11.8")) flag++;
if (deb_check(release:"3.0", prefix:"libc6-dev", reference:"2.2.5-11.8")) flag++;
if (deb_check(release:"3.0", prefix:"libc6-dev-sparc64", reference:"2.2.5-11.8")) flag++;
if (deb_check(release:"3.0", prefix:"libc6-pic", reference:"2.2.5-11.8")) flag++;
if (deb_check(release:"3.0", prefix:"libc6-prof", reference:"2.2.5-11.8")) flag++;
if (deb_check(release:"3.0", prefix:"libc6-sparc64", reference:"2.2.5-11.8")) flag++;
if (deb_check(release:"3.0", prefix:"libc6.1", reference:"2.2.5-11.8")) flag++;
if (deb_check(release:"3.0", prefix:"libc6.1-dbg", reference:"2.2.5-11.8")) flag++;
if (deb_check(release:"3.0", prefix:"libc6.1-dev", reference:"2.2.5-11.8")) flag++;
if (deb_check(release:"3.0", prefix:"libc6.1-pic", reference:"2.2.5-11.8")) flag++;
if (deb_check(release:"3.0", prefix:"libc6.1-prof", reference:"2.2.5-11.8")) flag++;
if (deb_check(release:"3.0", prefix:"locales", reference:"2.2.5-11.8")) flag++;
if (deb_check(release:"3.0", prefix:"nscd", reference:"2.2.5-11.8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
