#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3716. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(94922);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/05 16:04:16 $");

  script_cve_id("CVE-2016-5290", "CVE-2016-5291", "CVE-2016-5296", "CVE-2016-5297", "CVE-2016-9064", "CVE-2016-9066", "CVE-2016-9074");
  script_osvdb_id(147338, 147342, 147343, 147345, 147352, 147362, 147375, 147376, 147377, 147378, 147379, 147380, 147381, 147382, 147383, 147384, 147385, 147386);
  script_xref(name:"DSA", value:"3716");

  script_name(english:"Debian DSA-3716-1 : firefox-esr - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues have been found in the Mozilla Firefox web
browser: Multiple memory safety errors, buffer overflows and other
implementation errors may lead to the execution of arbitrary code or
bypass of the same-origin policy. Also, a man-in-the-middle attack in
the addon update mechanism has been fixed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/firefox-esr"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3716"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the firefox-esr packages.

For the stable distribution (jessie), these problems have been fixed
in version 45.5.0esr-1~deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"firefox-esr", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-dbg", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-dev", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-ach", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-af", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-all", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-an", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-ar", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-as", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-ast", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-az", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-be", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-bg", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-bn-bd", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-bn-in", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-br", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-bs", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-ca", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-cs", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-cy", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-da", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-de", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-dsb", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-el", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-en-gb", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-en-za", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-eo", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-es-ar", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-es-cl", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-es-es", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-es-mx", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-et", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-eu", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-fa", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-ff", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-fi", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-fr", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-fy-nl", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-ga-ie", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-gd", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-gl", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-gn", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-gu-in", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-he", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-hi-in", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-hr", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-hsb", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-hu", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-hy-am", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-id", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-is", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-it", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-ja", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-kk", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-km", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-kn", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-ko", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-lij", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-lt", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-lv", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-mai", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-mk", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-ml", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-mr", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-ms", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-nb-no", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-nl", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-nn-no", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-or", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-pa-in", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-pl", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-pt-br", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-pt-pt", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-rm", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-ro", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-ru", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-si", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-sk", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-sl", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-son", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-sq", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-sr", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-sv-se", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-ta", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-te", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-th", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-tr", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-uk", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-uz", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-vi", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-xh", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-zh-cn", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-zh-tw", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-dbg", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-dev", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ach", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-af", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-all", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-an", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ar", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-as", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ast", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-az", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-be", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-bg", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-bn-bd", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-bn-in", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-br", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-bs", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ca", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-cs", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-cy", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-da", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-de", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-dsb", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-el", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-en-gb", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-en-za", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-eo", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-es-ar", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-es-cl", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-es-es", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-es-mx", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-et", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-eu", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-fa", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ff", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-fi", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-fr", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-fy-nl", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ga-ie", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-gd", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-gl", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-gn", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-gu-in", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-he", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-hi-in", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-hr", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-hsb", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-hu", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-hy-am", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-id", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-is", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-it", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ja", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-kk", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-km", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-kn", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ko", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-lij", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-lt", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-lv", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-mai", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-mk", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ml", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-mr", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ms", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-nb-no", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-nl", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-nn-no", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-or", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-pa-in", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-pl", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-pt-br", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-pt-pt", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-rm", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ro", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ru", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-si", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-sk", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-sl", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-son", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-sq", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-sr", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-sv-se", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ta", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-te", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-th", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-tr", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-uk", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-uz", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-vi", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-xh", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-zh-cn", reference:"45.5.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-zh-tw", reference:"45.5.0esr-1~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
