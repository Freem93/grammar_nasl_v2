#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1586. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32435);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-1482", "CVE-2008-1686", "CVE-2008-1878");
  script_bugtraq_id(28370, 28665, 28816);
  script_xref(name:"DSA", value:"1586");

  script_name(english:"Debian DSA-1586-1 : xine-lib - multiple vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in xine-lib, a library
which supplies most of the application functionality of the xine
multimedia player. The Common Vulnerabilities and Exposures project
identifies the following three problems :

  - CVE-2008-1482
    Integer overflow vulnerabilities exist in xine's FLV,
    QuickTime, RealMedia, MVE and CAK demuxers, as well as
    the EBML parser used by the Matroska demuxer. These
    weaknesses allow an attacker to overflow heap buffers
    and potentially execute arbitrary code by supplying a
    maliciously crafted file of those types.

  - CVE-2008-1686
    Insufficient input validation in the Speex
    implementation used by this version of xine enables an
    invalid array access and the execution of arbitrary code
    by supplying a maliciously crafted Speex file.

  - CVE-2008-1878
    Inadequate bounds checking in the NES Sound Format (NSF)
    demuxer enables a stack-based buffer overflow and the
    execution of arbitrary code through a maliciously
    crafted NSF file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1482"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1586"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xine-lib packages.

For the stable distribution (etch), these problems have been fixed in
version 1.1.2+dfsg-7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xine-lib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/23");
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
if (deb_check(release:"4.0", prefix:"libxine-dev", reference:"1.1.2+dfsg-7")) flag++;
if (deb_check(release:"4.0", prefix:"libxine1", reference:"1.1.2+dfsg-7")) flag++;
if (deb_check(release:"4.0", prefix:"libxine1-dbg", reference:"1.1.2+dfsg-7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
