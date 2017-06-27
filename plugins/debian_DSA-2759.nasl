#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2759. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69959);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:43:09 $");

  script_cve_id("CVE-2013-1718", "CVE-2013-1722", "CVE-2013-1725", "CVE-2013-1730", "CVE-2013-1732", "CVE-2013-1735", "CVE-2013-1736", "CVE-2013-1737");
  script_osvdb_id(97388, 97389, 97390, 97391, 97392, 97398, 97401, 97404);
  script_xref(name:"DSA", value:"2759");

  script_name(english:"Debian DSA-2759-1 : iceweasel - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues have been found in Iceweasel, Debian's
version of the Mozilla Firefox web browser: Multiple memory safety
errors, buffer overflows may lead to the execution of arbitrary code.

The Iceweasel version in the oldstable distribution (squeeze) is no
longer supported with security updates."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/iceweasel"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2759"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the iceweasel packages.

For the stable distribution (wheezy), these problems have been fixed
in version 17.0.9esr-1~deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"iceweasel", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-dbg", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-dev", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ach", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-af", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-all", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-an", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ar", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-as", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ast", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-be", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-bg", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-bn-bd", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-bn-in", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-br", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-bs", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ca", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-cs", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-csb", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-cy", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-da", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-de", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-el", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-en-gb", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-en-za", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-eo", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-es-ar", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-es-cl", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-es-es", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-es-mx", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-et", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-eu", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-fa", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ff", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-fi", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-fr", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-fy-nl", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ga-ie", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-gd", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-gl", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-gu-in", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-he", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-hi-in", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-hr", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-hsb", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-hu", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-hy-am", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-id", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-is", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-it", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ja", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-kk", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-km", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-kn", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ko", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ku", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-lij", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-lt", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-lv", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-mai", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-mk", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ml", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-mr", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ms", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-nb-no", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-nl", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-nn-no", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-or", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-pa-in", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-pl", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-pt-br", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-pt-pt", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-rm", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ro", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ru", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-si", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-sk", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-sl", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-son", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-sq", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-sr", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-sv-se", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ta", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-te", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-th", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-tr", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-uk", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-vi", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-xh", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-zh-cn", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-zh-tw", reference:"17.0.9esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-zu", reference:"17.0.9esr-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
