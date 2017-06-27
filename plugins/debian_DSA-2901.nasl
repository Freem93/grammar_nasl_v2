#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2901. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73485);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/02/16 15:43:11 $");

  script_cve_id("CVE-2014-0165", "CVE-2014-0166");
  script_bugtraq_id(66765);
  script_osvdb_id(105620, 105630);
  script_xref(name:"DSA", value:"2901");

  script_name(english:"Debian DSA-2901-1 : wordpress - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Wordpress, a web blogging
tool. The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2014-0165
    A user with a contributor role, using a specially
    crafted request, can publish posts, which is reserved
    for users of the next-higher role.

  - CVE-2014-0166
    Jon Cave of the WordPress security team discovered that
    the wp_validate_auth_cookie function in
    wp-includes/pluggable.php does not properly determine
    the validity of authentication cookies, allowing a
    remote attacker to obtain access via a forged cookie."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=744018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/wordpress"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/wordpress"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2901"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wordpress packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 3.6.1+dfsg-1~deb6u2.

For the stable distribution (wheezy), these problems have been fixed
in version 3.6.1+dfsg-1~deb7u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"wordpress", reference:"3.6.1+dfsg-1~deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"wordpress-l10n", reference:"3.6.1+dfsg-1~deb6u2")) flag++;
if (deb_check(release:"7.0", prefix:"wordpress", reference:"3.6.1+dfsg-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"wordpress-l10n", reference:"3.6.1+dfsg-1~deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
