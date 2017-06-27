#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2388. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57542);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/16 15:31:56 $");

  script_cve_id("CVE-2010-2642", "CVE-2011-0433", "CVE-2011-0764", "CVE-2011-1552", "CVE-2011-1553", "CVE-2011-1554");
  script_bugtraq_id(45678, 46941, 47168, 47169);
  script_osvdb_id(70302, 72302, 74526, 74527, 74528, 74729);
  script_xref(name:"DSA", value:"2388");

  script_name(english:"Debian DSA-2388-1 : t1lib - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in t1lib, a Postscript Type 1
font rasterizer library, some of which might lead to code execution
through the opening of files embedding bad fonts.

  - CVE-2010-2642
    A heap-based buffer overflow in the AFM font metrics
    parser potentially leads to the execution of arbitrary
    code.

  - CVE-2011-0433
    Another heap-based buffer overflow in the AFM font
    metrics parser potentially leads to the execution of
    arbitrary code.

  - CVE-2011-0764
    An invalid pointer dereference allows execution of
    arbitrary code using crafted Type 1 fonts.

  - CVE-2011-1552
    Another invalid pointer dereference results in an
    application crash, triggered by crafted Type 1 fonts.

  - CVE-2011-1553
    A use-after-free vulnerability results in an application
    crash, triggered by crafted Type 1 fonts.

  - CVE-2011-1554
    An off-by-one error results in an invalid memory read
    and application crash, triggered by crafted Type 1
    fonts."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=652996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0433"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0764"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1552"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1553"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1554"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/t1lib"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2388"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the t1lib packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 5.1.2-3+lenny1.

For the stable distribution (squeeze), this problem has been fixed in
version 5.1.2-3+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:t1lib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"t1lib", reference:"5.1.2-3+lenny1")) flag++;
if (deb_check(release:"6.0", prefix:"libt1-5", reference:"5.1.2-3+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libt1-5-dbg", reference:"5.1.2-3+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libt1-dev", reference:"5.1.2-3+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libt1-doc", reference:"5.1.2-3+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"t1lib-bin", reference:"5.1.2-3+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
