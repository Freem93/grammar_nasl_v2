#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3323. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85162);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/05/05 16:01:12 $");

  script_cve_id("CVE-2014-6585", "CVE-2014-8146", "CVE-2014-8147", "CVE-2015-4760");
  script_osvdb_id(117232, 121624, 121625, 124617);
  script_xref(name:"DSA", value:"3323");

  script_name(english:"Debian DSA-3323-1 : icu - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in the International
Components for Unicode (ICU) library.

  - CVE-2014-8146
    The Unicode Bidirectional Algorithm implementation does
    not properly track directionally isolated pieces of
    text, which allows remote attackers to cause a denial of
    service (heap-based buffer overflow) or possibly execute
    arbitrary code via crafted text.

  - CVE-2014-8147
    The Unicode Bidirectional Algorithm implementation uses
    an integer data type that is inconsistent with a header
    file, which allows remote attackers to cause a denial of
    service (incorrect malloc followed by invalid free) or
    possibly execute arbitrary code via crafted text.

  - CVE-2015-4760
    The Layout Engine was missing multiple boundary checks.
    These could lead to buffer overflows and memory
    corruption. A specially crafted file could cause an
    application using ICU to parse untrusted font files to
    crash and, possibly, execute arbitrary code.

Additionally, it was discovered that the patch applied to ICU in
DSA-3187-1 for CVE-2014-6585 was incomplete, possibly leading to an
invalid memory access. This could allow remote attackers to disclose
portion of private memory via crafted font files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=778511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=784773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-8146"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-8147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-6585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/icu"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/icu"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3323"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the icu packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 4.8.1.1-12+deb7u3.

For the stable distribution (jessie), these problems have been fixed
in version 52.1-8+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"icu-doc", reference:"4.8.1.1-12+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libicu-dev", reference:"4.8.1.1-12+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libicu48", reference:"4.8.1.1-12+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libicu48-dbg", reference:"4.8.1.1-12+deb7u3")) flag++;
if (deb_check(release:"8.0", prefix:"icu-devtools", reference:"52.1-8+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"icu-doc", reference:"52.1-8+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libicu-dev", reference:"52.1-8+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libicu52", reference:"52.1-8+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libicu52-dbg", reference:"52.1-8+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
