#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3345. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85696);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2015/09/26 18:46:52 $");

  script_cve_id("CVE-2015-4497", "CVE-2015-4498");
  script_xref(name:"DSA", value:"3345");

  script_name(english:"Debian DSA-3345-1 : iceweasel - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues have been found in Iceweasel, Debian's
version of the Mozilla Firefox web browser. The Common Vulnerabilities
and Exposures project identifies the following problems :

  - CVE-2015-4497
    Jean-Max Reymond and Ucha Gobejishvili discovered a
    use-after-free vulnerability which occurs when resizing
    of a canvas element is triggered in concert with style
    changes. A web page containing malicious content can
    cause Iceweasel to crash, or potentially, execute
    arbitrary code with the privileges of the user running
    Iceweasel.

  - CVE-2015-4498
    Bas Venis reported a flaw in the handling of add-ons
    installation. A remote attacker can take advantage of
    this flaw to bypass the add-on installation prompt and
    trick a user into installing an add-on from a malicious
    source."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/iceweasel"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/iceweasel"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3345"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the iceweasel packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 38.2.1esr-1~deb7u1.

For the stable distribution (jessie), these problems have been fixed
in version 38.2.1esr-1~deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"iceweasel", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-dbg", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-dev", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ach", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-af", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-all", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-an", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ar", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-as", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ast", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-be", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-bg", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-bn-bd", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-bn-in", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-br", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-bs", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ca", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-cs", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-csb", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-cy", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-da", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-de", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-el", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-en-gb", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-en-za", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-eo", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-es-ar", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-es-cl", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-es-es", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-es-mx", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-et", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-eu", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-fa", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ff", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-fi", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-fr", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-fy-nl", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ga-ie", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-gd", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-gl", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-gu-in", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-he", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-hi-in", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-hr", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-hsb", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-hu", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-hy-am", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-id", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-is", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-it", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ja", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-kk", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-km", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-kn", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ko", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ku", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-lij", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-lt", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-lv", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-mai", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-mk", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ml", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-mr", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ms", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-nb-no", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-nl", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-nn-no", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-or", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-pa-in", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-pl", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-pt-br", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-pt-pt", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-rm", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ro", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ru", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-si", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-sk", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-sl", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-son", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-sq", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-sr", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-sv-se", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ta", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-te", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-th", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-tr", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-uk", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-vi", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-xh", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-zh-cn", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-zh-tw", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-zu", reference:"38.2.1esr-1~deb7u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-dbg", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-dev", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ach", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-af", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-all", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-an", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ar", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-as", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ast", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-be", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-bg", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-bn-bd", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-bn-in", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-br", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-bs", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ca", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-cs", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-csb", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-cy", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-da", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-de", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-el", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-en-gb", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-en-za", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-eo", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-es-ar", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-es-cl", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-es-es", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-es-mx", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-et", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-eu", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-fa", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ff", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-fi", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-fr", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-fy-nl", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ga-ie", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-gd", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-gl", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-gu-in", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-he", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-hi-in", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-hr", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-hsb", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-hu", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-hy-am", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-id", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-is", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-it", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ja", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-kk", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-km", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-kn", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ko", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ku", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-lij", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-lt", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-lv", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-mai", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-mk", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ml", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-mr", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ms", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-nb-no", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-nl", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-nn-no", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-or", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-pa-in", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-pl", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-pt-br", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-pt-pt", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-rm", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ro", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ru", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-si", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-sk", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-sl", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-son", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-sq", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-sr", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-sv-se", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-ta", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-te", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-th", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-tr", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-uk", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-vi", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-xh", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-zh-cn", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-zh-tw", reference:"38.2.1esr-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceweasel-l10n-zu", reference:"38.2.1esr-1~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
