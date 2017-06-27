#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1680. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35033);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-5050", "CVE-2008-5314");
  script_bugtraq_id(32207);
  script_xref(name:"DSA", value:"1680");

  script_name(english:"Debian DSA-1680-1 : clamav - buffer overflow, stack consumption");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Moritz Jodeit discovered that ClamAV, an anti-virus solution, suffers
from an off-by-one-error in its VBA project file processing, leading
to a heap-based buffer overflow and potentially arbitrary code
execution (CVE-2008-5050 ).

Ilja van Sprundel discovered that ClamAV contains a denial of service
condition in its JPEG file processing because it does not limit the
recursion depth when processing JPEG thumbnails (CVE-2008-5314 )."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=505134"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=507624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1680"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the clamav packages.

For the stable distribution (etch), these problems have been fixed in
version 0.90.1dfsg-4etch16."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"clamav", reference:"0.90.1dfsg-4etch16")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-base", reference:"0.90.1dfsg-4etch16")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-daemon", reference:"0.90.1dfsg-4etch16")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-dbg", reference:"0.90.1dfsg-4etch16")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-docs", reference:"0.90.1dfsg-4etch16")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-freshclam", reference:"0.90.1dfsg-4etch16")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-milter", reference:"0.90.1dfsg-4etch16")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-testfiles", reference:"0.90.1dfsg-4etch16")) flag++;
if (deb_check(release:"4.0", prefix:"libclamav-dev", reference:"0.90.1dfsg-4etch16")) flag++;
if (deb_check(release:"4.0", prefix:"libclamav2", reference:"0.90.1dfsg-4etch16")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
