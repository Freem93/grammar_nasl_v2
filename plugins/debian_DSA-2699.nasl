#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2699. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(66766);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/02/16 15:43:09 $");

  script_cve_id("CVE-2013-0773", "CVE-2013-0775", "CVE-2013-0776", "CVE-2013-0780", "CVE-2013-0782", "CVE-2013-0783", "CVE-2013-0787", "CVE-2013-0788", "CVE-2013-0793", "CVE-2013-0795", "CVE-2013-0796", "CVE-2013-0800", "CVE-2013-0801", "CVE-2013-1670", "CVE-2013-1674", "CVE-2013-1675", "CVE-2013-1676", "CVE-2013-1677", "CVE-2013-1678", "CVE-2013-1679", "CVE-2013-1680", "CVE-2013-1681");
  script_bugtraq_id(58037, 58041, 58042, 58043, 58044, 58047, 58391, 58819, 58825, 58831, 58836, 58837, 59855, 59858, 59859, 59860, 59861, 59862, 59863, 59864, 59865, 59868);
  script_xref(name:"DSA", value:"2699");

  script_name(english:"Debian DSA-2699-1 : iceweasel - several vulnerabilities");
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
errors, missing input sanitising vulnerabilities, use-after-free
vulnerabilities, buffer overflows and other programming errors may
lead to the execution of arbitrary code, privilege escalation,
information leaks or cross-site-scripting.

We're changing the approach for security updates for Iceweasel,
Icedove and Iceape in stable-security: Instead of backporting security
fixes, we now provide releases based on the Extended Support Release
branch. As such, this update introduces packages based on Firefox 17
and at some point in the future we will switch to the next ESR branch
once ESR 17 has reached it's end of life.

Some Xul extensions currently packaged in the Debian archive are not
compatible with the new browser engine. Up-to-date and compatible
versions can be retrieved from http://addons.mozilla.org as a short
term solution. A solution to keep packaged extensions compatible with
the Mozilla releases is still being sorted out.

We don't have the resources to backport security fixes to the
Iceweasel release in oldstable-security any longer. If you're up to
the task and want to help, please get in touch with
team@security.debian.org. Otherwise, we'll announce the end of
security support for Iceweasel, Icedove and Iceape in Squeeze in the
next update round."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://addons.mozilla.org"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/iceweasel"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2699"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the iceweasel packages.

For the stable distribution (wheezy), these problems have been fixed
in version 17.0.6esr-1~deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/03");
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
if (deb_check(release:"7.0", prefix:"iceweasel", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-dbg", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-dev", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ach", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-af", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-all", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-an", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ar", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-as", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ast", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-be", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-bg", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-bn-bd", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-bn-in", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-br", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-bs", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ca", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-cs", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-csb", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-cy", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-da", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-de", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-el", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-en-gb", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-en-za", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-eo", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-es-ar", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-es-cl", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-es-es", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-es-mx", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-et", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-eu", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-fa", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ff", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-fi", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-fr", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-fy-nl", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ga-ie", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-gd", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-gl", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-gu-in", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-he", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-hi-in", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-hr", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-hsb", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-hu", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-hy-am", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-id", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-is", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-it", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ja", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-kk", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-km", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-kn", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ko", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ku", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-lij", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-lt", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-lv", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-mai", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-mk", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ml", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-mr", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ms", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-nb-no", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-nl", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-nn-no", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-or", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-pa-in", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-pl", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-pt-br", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-pt-pt", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-rm", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ro", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ru", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-si", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-sk", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-sl", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-son", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-sq", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-sr", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-sv-se", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ta", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-te", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-th", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-tr", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-uk", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-vi", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-xh", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-zh-cn", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-zh-tw", reference:"17.0.6esr-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-zu", reference:"17.0.6esr-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
