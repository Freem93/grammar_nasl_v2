#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3640. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(92731);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/06 20:25:09 $");

  script_cve_id("CVE-2016-2830", "CVE-2016-2836", "CVE-2016-2837", "CVE-2016-2838", "CVE-2016-5252", "CVE-2016-5254", "CVE-2016-5258", "CVE-2016-5259", "CVE-2016-5262", "CVE-2016-5263", "CVE-2016-5264", "CVE-2016-5265");
  script_osvdb_id(142419, 142420, 142421, 142422, 142423, 142424, 142425, 142426, 142468, 142474, 142476, 142478, 142479, 142480, 142481, 142482, 142484, 142485, 142486);
  script_xref(name:"DSA", value:"3640");

  script_name(english:"Debian DSA-3640-1 : firefox-esr - security update");
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
implementation errors may lead to the execution of arbitrary code,
cross-site scripting, information disclosure and bypass of the
same-origin policy."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/firefox-esr"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3640"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the firefox-esr packages.

For the stable distribution (jessie), these problems have been fixed
in version 45.3.0esr-1~deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/05");
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
if (deb_check(release:"8.0", prefix:"firefox-esr", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-dbg", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-dev", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-ach", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-af", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-all", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-an", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-ar", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-as", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-ast", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-az", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-be", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-bg", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-bn-bd", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-bn-in", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-br", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-bs", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-ca", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-cs", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-cy", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-da", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-de", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-dsb", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-el", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-en-gb", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-en-za", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-eo", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-es-ar", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-es-cl", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-es-es", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-es-mx", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-et", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-eu", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-fa", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-ff", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-fi", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-fr", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-fy-nl", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-ga-ie", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-gd", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-gl", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-gn", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-gu-in", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-he", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-hi-in", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-hr", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-hsb", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-hu", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-hy-am", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-id", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-is", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-it", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-ja", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-kk", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-km", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-kn", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-ko", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-lij", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-lt", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-lv", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-mai", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-mk", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-ml", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-mr", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-ms", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-nb-no", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-nl", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-nn-no", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-or", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-pa-in", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-pl", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-pt-br", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-pt-pt", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-rm", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-ro", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-ru", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-si", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-sk", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-sl", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-son", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-sq", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-sr", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-sv-se", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-ta", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-te", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-th", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-tr", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-uk", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-uz", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-vi", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-xh", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-zh-cn", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"firefox-esr-l10n-zh-tw", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-dbg", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-dev", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ach", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-af", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-all", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-an", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ar", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-as", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ast", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-az", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-be", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-bg", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-bn-bd", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-bn-in", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-br", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-bs", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ca", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-cs", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-cy", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-da", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-de", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-dsb", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-el", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-en-gb", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-en-za", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-eo", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-es-ar", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-es-cl", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-es-es", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-es-mx", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-et", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-eu", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-fa", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ff", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-fi", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-fr", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-fy-nl", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ga-ie", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-gd", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-gl", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-gn", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-gu-in", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-he", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-hi-in", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-hr", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-hsb", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-hu", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-hy-am", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-id", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-is", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-it", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ja", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-kk", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-km", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-kn", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ko", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-lij", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-lt", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-lv", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-mai", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-mk", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ml", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-mr", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ms", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-nb-no", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-nl", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-nn-no", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-or", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-pa-in", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-pl", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-pt-br", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-pt-pt", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-rm", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ro", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ru", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-si", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-sk", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-sl", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-son", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-sq", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-sr", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-sv-se", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ta", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-te", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-th", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-tr", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-uk", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-uz", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-vi", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-xh", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-zh-cn", reference:"45.3.0esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-zh-tw", reference:"45.3.0esr-1~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
