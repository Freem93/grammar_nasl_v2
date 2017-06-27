#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3332. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85355);
  script_version("$Revision: 2.11 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2015-2213", "CVE-2015-5622", "CVE-2015-5730", "CVE-2015-5731", "CVE-2015-5732", "CVE-2015-5734");
  script_osvdb_id(125761, 125763, 125764, 125765, 125766);
  script_xref(name:"DSA", value:"3332");

  script_name(english:"Debian DSA-3332-1 : wordpress - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been fixed in Wordpress, the popular
blogging engine.

  - CVE-2015-2213
    SQL Injection allowed a remote attacker to compromise
    the site.

  - CVE-2015-5622
    The robustness of the shortcodes HTML tags filter has
    been improved. The parsing is a bit more strict, which
    may affect your installation. This is the corrected
    version of the patch that needed to be reverted in DSA
    3328-2.

  - CVE-2015-5730
    A potential timing side-channel attack in widgets.

  - CVE-2015-5731
    An attacker could lock a post that was being edited.

  - CVE-2015-5732
    Cross site scripting in a widget title allows an
    attacker to steal sensitive information.

  - CVE-2015-5734
    Fix some broken links in the legacy theme preview.

The issues were discovered by Marc-Alexandre Montpas of Sucuri, Helen
Hou-Sandi of the WordPress security team, Netanel Rubin of Check
Point, Ivan Grigorov, Johannes Schmitt of Scrutinizer and Mohamed A.
Baset."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=794548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=794560"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-2213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5622"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5730"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/wordpress"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3332"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wordpress packages.

For the stable distribution (jessie), these problems have been fixed
in version 4.1+dfsg-1+deb8u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/13");
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
if (deb_check(release:"8.0", prefix:"wordpress", reference:"4.1+dfsg-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"wordpress-l10n", reference:"4.1+dfsg-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"wordpress-theme-twentyfifteen", reference:"4.1+dfsg-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"wordpress-theme-twentyfourteen", reference:"4.1+dfsg-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"wordpress-theme-twentythirteen", reference:"4.1+dfsg-1+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
