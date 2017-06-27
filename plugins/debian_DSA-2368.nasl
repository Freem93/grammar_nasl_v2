#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2368. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57508);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/22 14:14:58 $");

  script_cve_id("CVE-2011-3389", "CVE-2011-4362");
  script_bugtraq_id(49778, 50851);
  script_osvdb_id(74829, 77366);
  script_xref(name:"DSA", value:"2368");

  script_name(english:"Debian DSA-2368-1 : lighttpd - multiple vulnerabilities (BEAST)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in lighttpd, a small and
fast webserver with minimal memory footprint.

  - CVE-2011-4362
    Xi Wang discovered that the base64 decoding routine
    which is used to decode user input during an HTTP
    authentication, suffers of a signedness issue when
    processing user input. As a result it is possible to
    force lighttpd to perform an out-of-bounds read which
    results in Denial of Service conditions.

  - CVE-2011-3389
    When using CBC ciphers on an SSL enabled virtual host to
    communicate with certain client, a so called 'BEAST'
    attack allows man-in-the-middle attackers to obtain
    plaintext HTTP traffic via a blockwise chosen-boundary
    attack (BCBA) on an HTTPS session. Technically this is
    no lighttpd vulnerability. However, lighttpd offers a
    workaround to mitigate this problem by providing a
    possibility to disable CBC ciphers.

  This updates includes this option by default. System administrators
  are advised to read the NEWS file of this update (as this may break
  older clients)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=652726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3389"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/lighttpd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2368"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the lighttpd packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.4.19-5+lenny3.

For the stable distribution (squeeze), this problem has been fixed in
version 1.4.28-2+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/20");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/12");
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
if (deb_check(release:"5.0", prefix:"lighttpd", reference:"1.4.19-5+lenny3")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd", reference:"1.4.28-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-doc", reference:"1.4.28-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-mod-cml", reference:"1.4.28-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-mod-magnet", reference:"1.4.28-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-mod-mysql-vhost", reference:"1.4.28-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-mod-trigger-b4-dl", reference:"1.4.28-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-mod-webdav", reference:"1.4.28-2+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
