#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1684. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35077);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-5316", "CVE-2008-5317");
  script_xref(name:"DSA", value:"1684");

  script_name(english:"Debian DSA-1684-1 : lcms - multiple vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities have been found in lcms, a library and set of
commandline utilities for image color management. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2008-5316
    Inadequate enforcement of fixed-length buffer limits
    allows an attacker to overflow a buffer on the stack,
    potentially enabling the execution of arbitrary code
    when a maliciously-crafted image is opened.

  - CVS-2008-5317

    An integer sign error in reading image gamma data could
    allow an attacker to cause an under-sized buffer to be
    allocated for subsequent image data, with unknown
    consequences potentially including the execution of
    arbitrary code if a maliciously-crafted image is opened."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5316"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVS-2008-5317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1684"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the lcms packages.

For the stable distribution (etch), these problems have been fixed in
version 1.15-1.1+etch1.

For the upcoming stable distribution (lenny), and the unstable
distribution (sid), these problems are fixed in version 1.17.dfsg-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lcms");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/10");
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
if (deb_check(release:"4.0", prefix:"liblcms-utils", reference:"1.15-1.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"liblcms1", reference:"1.15-1.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"liblcms1-dev", reference:"1.15-1.1+etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
