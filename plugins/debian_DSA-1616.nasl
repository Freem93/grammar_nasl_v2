#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1616. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33568);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/03/19 14:28:19 $");

  script_cve_id("CVE-2008-2713", "CVE-2008-3215");
  script_bugtraq_id(29750);
  script_osvdb_id(46241);
  script_xref(name:"DSA", value:"1616");

  script_name(english:"Debian DSA-1616-2 : clamav - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Damian Put discovered a vulnerability in the ClamAV anti-virus
toolkit's parsing of Petite-packed Win32 executables. The weakness
leads to an invalid memory access, and could enable an attacker to
crash clamav by supplying a maliciously crafted Petite-compressed
binary for scanning. In some configurations, such as when clamav is
used in combination with mail servers, this could cause a system to
'fail open', facilitating a follow-on viral attack.

A previous version of this advisory referenced packages that were
built incorrectly and omitted the intended correction. This issue was
fixed in packages referenced by the -2 revision of the advisory.

The Common Vulnerabilities and Exposures project identifies this
weakness as CVE-2008-2713 and CVE-2008-3215."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=490925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3215"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1616"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the clamav packages.

For the stable distribution (etch), this problem has been fixed in
version 0.90.1dfsg-3.1+etch14."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"clamav", reference:"0.90.1dfsg-3.1+etch14")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-base", reference:"0.90.1dfsg-3.1+etch14")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-daemon", reference:"0.90.1dfsg-3.1+etch14")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-dbg", reference:"0.90.1dfsg-3.1+etch14")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-docs", reference:"0.90.1dfsg-3.1+etch14")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-freshclam", reference:"0.90.1dfsg-3.1+etch14")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-milter", reference:"0.90.1dfsg-3.1+etch14")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-testfiles", reference:"0.90.1dfsg-3.1+etch14")) flag++;
if (deb_check(release:"4.0", prefix:"libclamav-dev", reference:"0.90.1dfsg-3.1+etch14")) flag++;
if (deb_check(release:"4.0", prefix:"libclamav2", reference:"0.90.1dfsg-3.1+etch14")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
