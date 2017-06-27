#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1320. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25586);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2007-2650", "CVE-2007-3023", "CVE-2007-3024", "CVE-2007-3025", "CVE-2007-3122", "CVE-2007-3123");
  script_osvdb_id(34915, 35522, 36908, 45392);
  script_xref(name:"DSA", value:"1320");

  script_name(english:"Debian DSA-1320-1 : clamav - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in the Clam
anti-virus toolkit. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2007-2650
    It was discovered that the OLE2 parser can be tricked
    into an infinite loop and memory exhaustion.

  - CVE-2007-3023
    It was discovered that the NsPack decompression code
    performed insufficient sanitising on an internal length
    variable, resulting in a potential buffer overflow.

  - CVE-2007-3024
    It was discovered that temporary files were created with
    insecure permissions, resulting in information
    disclosure.

  - CVE-2007-3122
    It was discovered that the decompression code for RAR
    archives allows bypassing a scan of a RAR archive due to
    insufficient validity checks.

  - CVE-2007-3123
    It was discovered that the decompression code for RAR
    archives performs insufficient validation of header
    values, resulting in a buffer overflow."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2650"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3122"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1320"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the clamav packages. An updated package for oldstable/powerpc
is not yet available. It will be provided later.

For the oldstable distribution (sarge) these problems have been fixed
in version 0.84-2.sarge.17. Please note that the fix for CVE-2007-3024
hasn't been backported to oldstable.

For the stable distribution (etch) these problems have been fixed in
version 0.90.1-3etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"clamav", reference:"0.84-2.sarge.17")) flag++;
if (deb_check(release:"3.1", prefix:"clamav-base", reference:"0.84-2.sarge.17")) flag++;
if (deb_check(release:"3.1", prefix:"clamav-daemon", reference:"0.84-2.sarge.17")) flag++;
if (deb_check(release:"3.1", prefix:"clamav-docs", reference:"0.84-2.sarge.17")) flag++;
if (deb_check(release:"3.1", prefix:"clamav-freshclam", reference:"0.84-2.sarge.17")) flag++;
if (deb_check(release:"3.1", prefix:"clamav-milter", reference:"0.84-2.sarge.17")) flag++;
if (deb_check(release:"3.1", prefix:"clamav-testfiles", reference:"0.84-2.sarge.17")) flag++;
if (deb_check(release:"3.1", prefix:"libclamav-dev", reference:"0.84-2.sarge.17")) flag++;
if (deb_check(release:"3.1", prefix:"libclamav1", reference:"0.84-2.sarge.17")) flag++;
if (deb_check(release:"4.0", prefix:"clamav", reference:"0.90.1-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-base", reference:"0.90.1-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-daemon", reference:"0.90.1-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-dbg", reference:"0.90.1-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-docs", reference:"0.90.1-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-freshclam", reference:"0.90.1-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-milter", reference:"0.90.1-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-testfiles", reference:"0.90.1-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libclamav-dev", reference:"0.90.1-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libclamav2", reference:"0.90.1-3etch3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
