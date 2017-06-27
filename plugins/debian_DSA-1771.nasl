#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1771. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36164);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-6680", "CVE-2009-1270");
  script_osvdb_id(53461, 53598);
  script_xref(name:"DSA", value:"1771");

  script_name(english:"Debian DSA-1771-1 : clamav - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the ClamAV anti-virus
toolkit :

  - CVE-2008-6680
    Attackers can cause a denial of service (crash) via a
    crafted EXE file that triggers a divide-by-zero error.

  - CVE-2009-1270
    Attackers can cause a denial of service (infinite loop)
    via a crafted tar file that causes (1) clamd and (2)
    clamscan to hang.

  - (no CVE Id yet)

    Attackers can cause a denial of service (crash) via a
    crafted EXE file that crashes the UPack unpacker."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-6680"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1270"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1771"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the clamav packages.

For the old stable distribution (etch), these problems have been fixed
in version 0.90.1dfsg-4etch19.

For the stable distribution (lenny), these problems have been fixed in
version 0.94.dfsg.2-1lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(94, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"clamav", reference:"0.90.1dfsg-4etch19")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-base", reference:"0.90.1dfsg-4etch19")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-daemon", reference:"0.90.1dfsg-4etch19")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-dbg", reference:"0.90.1dfsg-4etch19")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-docs", reference:"0.90.1dfsg-4etch19")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-freshclam", reference:"0.90.1dfsg-4etch19")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-milter", reference:"0.90.1dfsg-4etch19")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-testfiles", reference:"0.90.1dfsg-4etch19")) flag++;
if (deb_check(release:"4.0", prefix:"libclamav-dev", reference:"0.90.1dfsg-4etch19")) flag++;
if (deb_check(release:"4.0", prefix:"libclamav2", reference:"0.90.1dfsg-4etch19")) flag++;
if (deb_check(release:"5.0", prefix:"clamav", reference:"0.94.dfsg.2-1lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"clamav-base", reference:"0.94.dfsg.2-1lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"clamav-daemon", reference:"0.94.dfsg.2-1lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"clamav-dbg", reference:"0.94.dfsg.2-1lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"clamav-docs", reference:"0.94.dfsg.2-1lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"clamav-freshclam", reference:"0.94.dfsg.2-1lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"clamav-milter", reference:"0.94.dfsg.2-1lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"clamav-testfiles", reference:"0.94.dfsg.2-1lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libclamav-dev", reference:"0.94.dfsg.2-1lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libclamav5", reference:"0.94.dfsg.2-1lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
