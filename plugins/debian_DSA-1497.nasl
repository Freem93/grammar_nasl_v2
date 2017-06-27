#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1497. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31102);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-6595", "CVE-2008-0318");
  script_bugtraq_id(27751);
  script_osvdb_id(42296, 42297, 43337, 43338);
  script_xref(name:"DSA", value:"1497");

  script_name(english:"Debian DSA-1497-1 : clamav - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Clam anti-virus
toolkit, which may lead to the execution of arbitrary code or local
denial of service. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2007-6595
    It was discovered that temporary files are created
    insecurely, which may result in local denial of service
    by overwriting files.

  - CVE-2008-0318
    Silvio Cesare discovered an integer overflow in the
    parser for PE headers.

The version of clamav in the old stable distribution (sarge) is no
longer supported with security updates."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-6595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1497"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the clamav packages.

For the stable distribution (etch), these problems have been fixed in
version 0.90.1dfsg-3etch10. In addition to these fixes, this update
also incorporates changes from the upcoming point release of the
stable distribution (non-free RAR handling code was removed)."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(59, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/18");
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
if (deb_check(release:"4.0", prefix:"clamav", reference:"0.90.1dfsg-3etch10")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-base", reference:"0.90.1dfsg-3etch10")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-daemon", reference:"0.90.1dfsg-3etch10")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-dbg", reference:"0.90.1dfsg-3etch10")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-docs", reference:"0.90.1dfsg-3etch10")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-freshclam", reference:"0.90.1dfsg-3etch10")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-milter", reference:"0.90.1dfsg-3etch10")) flag++;
if (deb_check(release:"4.0", prefix:"clamav-testfiles", reference:"0.90.1dfsg-3etch10")) flag++;
if (deb_check(release:"4.0", prefix:"libclamav-dev", reference:"0.90.1dfsg-3etch10")) flag++;
if (deb_check(release:"4.0", prefix:"libclamav2", reference:"0.90.1dfsg-3etch10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
