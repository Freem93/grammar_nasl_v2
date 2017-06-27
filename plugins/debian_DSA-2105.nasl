#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2105. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49150);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/19 17:45:43 $");

  script_cve_id("CVE-2010-1797", "CVE-2010-2541", "CVE-2010-2805", "CVE-2010-2806", "CVE-2010-2807", "CVE-2010-2808", "CVE-2010-3053");
  script_bugtraq_id(42241, 42285, 42624);
  script_xref(name:"DSA", value:"2105");

  script_name(english:"Debian DSA-2105-1 : freetype - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the FreeType font
library. The Common Vulnerabilities and Exposures project identifies
the following problems :

  - CVE-2010-1797
    Multiple stack-based buffer overflows in the
    cff_decoder_parse_charstrings function in the CFF Type2
    CharStrings interpreter in cff/cffgload.c in FreeType
    allow remote attackers to execute arbitrary code or
    cause a denial of service (memory corruption) via
    crafted CFF opcodes in embedded fonts in a PDF document,
    as demonstrated by JailbreakMe.

  - CVE-2010-2541
    Buffer overflow in ftmulti.c in the ftmulti demo program
    in FreeType allows remote attackers to cause a denial of
    service (application crash) or possibly execute
    arbitrary code via a crafted font file.

  - CVE-2010-2805
    The FT_Stream_EnterFrame function in base/ftstream.c in
    FreeType does not properly validate certain position
    values, which allows remote attackers to cause a denial
    of service (application crash) or possibly execute
    arbitrary code via a crafted font file

  - CVE-2010-2806
    Array index error in the t42_parse_sfnts function in
    type42/t42parse.c in FreeType allows remote attackers to
    cause a denial of service (application crash) or
    possibly execute arbitrary code via negative size values
    for certain strings in FontType42 font files, leading to
    a heap-based buffer overflow.

  - CVE-2010-2807
    FreeType uses incorrect integer data types during bounds
    checking, which allows remote attackers to cause a
    denial of service (application crash) or possibly
    execute arbitrary code via a crafted font file.

  - CVE-2010-2808
    Buffer overflow in the Mac_Read_POST_Resource function
    in base/ftobjs.c in FreeType allows remote attackers to
    cause a denial of service (memory corruption and
    application crash) or possibly execute arbitrary code
    via a crafted Adobe Type 1 Mac Font File (aka LWFN)
    font.

  - CVE-2010-3053
    bdf/bdflib.c in FreeType allows remote attackers to
    cause a denial of service (application crash) via a
    crafted BDF font file, related to an attempted
    modification of a value in a static string."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1797"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2541"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2105"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the freetype package.

For the stable distribution (lenny), these problems have been fixed in
version 2.3.7-2+lenny3"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freetype");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"freetype2-demos", reference:"2.3.7-2+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"libfreetype6", reference:"2.3.7-2+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"libfreetype6-dev", reference:"2.3.7-2+lenny3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
