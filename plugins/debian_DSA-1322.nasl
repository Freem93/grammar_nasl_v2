#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1322. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25616);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/01/14 15:38:18 $");

  script_cve_id("CVE-2007-3390", "CVE-2007-3392", "CVE-2007-3393");
  script_osvdb_id(37639, 37640, 37641, 37642, 37643);
  script_xref(name:"DSA", value:"1322");

  script_name(english:"Debian DSA-1322-1 : wireshark - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in the Wireshark
network traffic analyzer, which may lead to denial of service. The
Common Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2007-3390
    Off-by-one overflows were discovered in the iSeries
    dissector.

  - CVE-2007-3392
    The MMS and SSL dissectors could be forced into an
    infinite loop.

  - CVE-2007-3393
    An off-by-one overflow was discovered in the DHCP/BOOTP
    dissector.

The oldstable distribution (sarge) is not affected by these problems.
(In Sarge Wireshark used to be called Ethereal)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3390"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1322"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Wireshark packages.

For the stable distribution (etch) these problems have been fixed in
version 0.99.4-5.etch.0. Packages for the big endian MIPS architecture
are not yet available. They will be provided later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/30");
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
if (deb_check(release:"4.0", prefix:"ethereal", reference:"0.99.4-5.etch.0")) flag++;
if (deb_check(release:"4.0", prefix:"ethereal-common", reference:"0.99.4-5.etch.0")) flag++;
if (deb_check(release:"4.0", prefix:"ethereal-dev", reference:"0.99.4-5.etch.0")) flag++;
if (deb_check(release:"4.0", prefix:"tethereal", reference:"0.99.4-5.etch.0")) flag++;
if (deb_check(release:"4.0", prefix:"tshark", reference:"0.99.4-5.etch.0")) flag++;
if (deb_check(release:"4.0", prefix:"wireshark", reference:"0.99.4-5.etch.0")) flag++;
if (deb_check(release:"4.0", prefix:"wireshark-common", reference:"0.99.4-5.etch.0")) flag++;
if (deb_check(release:"4.0", prefix:"wireshark-dev", reference:"0.99.4-5.etch.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
