#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2881. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73106);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/19 17:45:44 $");

  script_cve_id("CVE-2014-1493", "CVE-2014-1497", "CVE-2014-1505", "CVE-2014-1508", "CVE-2014-1510", "CVE-2014-1511", "CVE-2014-1512", "CVE-2014-1513", "CVE-2014-1514");
  script_bugtraq_id(66203, 66206, 66207, 66209, 66240);
  script_xref(name:"DSA", value:"2881");

  script_name(english:"Debian DSA-2881-1 : iceweasel - security update");
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
errors, out of bound reads, use-after-frees and other implementation
errors may lead to the execution of arbitrary code, information
disclosure, denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/iceweasel"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2881"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the iceweasel packages.

For the stable distribution (wheezy), these problems have been fixed
in version 24.4.0esr-1~deb7u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox WebIDL Privileged Javascript Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"iceweasel", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-dbg", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-dev", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ach", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-af", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-all", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-an", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ar", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-as", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ast", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-be", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-bg", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-bn-bd", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-bn-in", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-br", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-bs", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ca", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-cs", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-csb", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-cy", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-da", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-de", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-el", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-en-gb", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-en-za", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-eo", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-es-ar", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-es-cl", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-es-es", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-es-mx", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-et", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-eu", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-fa", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ff", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-fi", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-fr", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-fy-nl", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ga-ie", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-gd", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-gl", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-gu-in", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-he", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-hi-in", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-hr", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-hsb", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-hu", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-hy-am", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-id", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-is", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-it", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ja", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-kk", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-km", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-kn", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ko", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ku", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-lij", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-lt", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-lv", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-mai", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-mk", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ml", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-mr", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ms", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-nb-no", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-nl", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-nn-no", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-or", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-pa-in", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-pl", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-pt-br", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-pt-pt", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-rm", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ro", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ru", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-si", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-sk", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-sl", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-son", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-sq", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-sr", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-sv-se", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-ta", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-te", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-th", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-tr", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-uk", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-vi", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-xh", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-zh-cn", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-zh-tw", reference:"24.4.0esr-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"iceweasel-l10n-zu", reference:"24.4.0esr-1~deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
