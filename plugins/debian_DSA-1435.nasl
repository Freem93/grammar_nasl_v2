#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1435. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29755);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/03/19 14:28:18 $");

  script_cve_id("CVE-2007-6335", "CVE-2007-6336");
  script_bugtraq_id(26927);
  script_osvdb_id(42294, 42295);
  script_xref(name:"DSA", value:"1435");

  script_name(english:"Debian DSA-1435-1 : clamav - several vulnerabilities");
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

  - CVE-2007-6335
    It was discovered that an integer overflow in the
    decompression code for MEW archives may lead to the
    execution of arbitrary code.

  - CVE-2007-6336
    It was discovered that on off-by-one in the MS-ZIP
    decompression code may lead to the execution of
    arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-6335"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-6336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1435"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the clamav packages.

The old stable distribution (sarge) is not affected by these problems.
However, since the clamav version from Sarge cannot process all
current Clam malware signatures any longer, support for the ClamAV in
Sarge is now discontinued. We recommend to upgrade to the stable
distribution or run a backport of the stable version.

For the stable distribution (etch) these problems have been fixed in
version 0.90.1-3etch8."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119,189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"clamav", reference:"0.90.1-3etch8")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-base", reference:"0.90.1-3etch8")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-daemon", reference:"0.90.1-3etch8")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-dbg", reference:"0.90.1-3etch8")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-docs", reference:"0.90.1-3etch8")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-freshclam", reference:"0.90.1-3etch8")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-milter", reference:"0.90.1-3etch8")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-testfiles", reference:"0.90.1-3etch8")) flag++;
if (deb_check(release:"4.0", prefix:"libclamav-dev", reference:"0.90.1-3etch8")) flag++;
if (deb_check(release:"4.0", prefix:"libclamav2", reference:"0.90.1-3etch8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
