#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1137. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22679);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/09/26 13:31:37 $");

  script_cve_id("CVE-2006-3459", "CVE-2006-3460", "CVE-2006-3461", "CVE-2006-3462", "CVE-2006-3463", "CVE-2006-3464", "CVE-2006-3465");
  script_osvdb_id(27723, 27724, 27725, 27726, 27727, 27728, 27729);
  script_xref(name:"DSA", value:"1137");

  script_name(english:"Debian DSA-1137-1 : tiff - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tavis Ormandy of the Google Security Team discovered several problems
in the TIFF library. The Common Vulnerabilities and Exposures project
identifies the following issues :

  - CVE-2006-3459
    Several stack-buffer overflows have been discovered.

  - CVE-2006-3460
    A heap overflow vulnerability in the JPEG decoder may
    overrun a buffer with more data than expected.

  - CVE-2006-3461
    A heap overflow vulnerability in the PixarLog decoder
    may allow an attacker to execute arbitrary code.

  - CVE-2006-3462
    A heap overflow vulnerability has been discovered in the
    NeXT RLE decoder.

  - CVE-2006-3463
    An loop was discovered where a 16bit unsigned short was
    used to iterate over a 32bit unsigned value so that the
    loop would never terminate and continue forever.

  - CVE-2006-3464
    Multiple unchecked arithmetic operations were uncovered,
    including a number of the range checking operations
    designed to ensure the offsets specified in TIFF
    directories are legitimate.

  - CVE-2006-3465
    A flaw was also uncovered in libtiffs custom tag support
    which may result in abnormal behaviour, crashes, or
    potentially arbitrary code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1137"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libtiff packages.

For the stable distribution (sarge) these problems have been fixed in
version 3.7.2-7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apple iOS MobileMail LibTIFF Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libtiff-opengl", reference:"3.7.2-7")) flag++;
if (deb_check(release:"3.1", prefix:"libtiff-tools", reference:"3.7.2-7")) flag++;
if (deb_check(release:"3.1", prefix:"libtiff4", reference:"3.7.2-7")) flag++;
if (deb_check(release:"3.1", prefix:"libtiff4-dev", reference:"3.7.2-7")) flag++;
if (deb_check(release:"3.1", prefix:"libtiffxx0", reference:"3.7.2-7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
