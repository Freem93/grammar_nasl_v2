#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1745. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35967);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2009-0581", "CVE-2009-0723", "CVE-2009-0733");
  script_bugtraq_id(34185);
  script_osvdb_id(56307, 56308);
  script_xref(name:"DSA", value:"1745");

  script_name(english:"Debian DSA-1745-1 : lcms - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security issues have been discovered in lcms, a color
management library. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2009-0581
    Chris Evans discovered that lcms is affected by a memory
    leak, which could result in a denial of service via
    specially crafted image files.

  - CVE-2009-0723
    Chris Evans discovered that lcms is prone to several
    integer overflows via specially crafted image files,
    which could lead to the execution of arbitrary code.

  - CVE-2009-0733
    Chris Evans discovered the lack of upper-bounds check on
    sizes leading to a buffer overflow, which could be used
    to execute arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1745"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the lcms packages.

For the stable distribution (lenny), these problems have been fixed in
version 1.17.dfsg-1+lenny1.

For the oldstable distribution (etch), these problems have been fixed
in version 1.15-1.1+etch2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lcms");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"liblcms-utils", reference:"1.15-1.1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"liblcms1", reference:"1.15-1.1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"liblcms1-dev", reference:"1.15-1.1+etch2")) flag++;
if (deb_check(release:"5.0", prefix:"liblcms-utils", reference:"1.17.dfsg-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"liblcms1", reference:"1.17.dfsg-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"liblcms1-dev", reference:"1.17.dfsg-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"python-liblcms", reference:"1.17.dfsg-1+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
