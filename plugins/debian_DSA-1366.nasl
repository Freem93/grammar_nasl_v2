#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1366. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25966);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2007-4510", "CVE-2007-4560");
  script_osvdb_id(36909, 36910, 36911);
  script_xref(name:"DSA", value:"1366");

  script_name(english:"Debian DSA-1366-1 : clamav - several vulnerabilities");
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

  - CVE-2007-4510
    It was discovered that the RTF and RFC2397 parsers can
    be tricked into dereferencing a NULL pointer, resulting
    in denial of service.

  - CVE-2007-4560
    It was discovered that clamav-milter performs
    insufficient input sanitising, resulting in the
    execution of arbitrary shell commands.

The oldstable distribution (sarge) is only affected by a subset of the
problems. An update will be provided later."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4560"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1366"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the clamav packages. 

For the stable distribution (etch) these problems have been fixed in
version 0.90.1-3etch7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ClamAV Milter Blackhole-Mode Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(78);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/22");
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
if (deb_check(release:"4.0", prefix:"clamav", reference:"0.90.1-3etch7")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-base", reference:"0.90.1-3etch7")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-daemon", reference:"0.90.1-3etch7")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-dbg", reference:"0.90.1-3etch7")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-docs", reference:"0.90.1-3etch7")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-freshclam", reference:"0.90.1-3etch7")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-milter", reference:"0.90.1-3etch7")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-testfiles", reference:"0.90.1-3etch7")) flag++;
if (deb_check(release:"4.0", prefix:"libclamav-dev", reference:"0.90.1-3etch7")) flag++;
if (deb_check(release:"4.0", prefix:"libclamav2", reference:"0.90.1-3etch7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
