#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2757. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69895);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/02/16 15:43:09 $");

  script_cve_id("CVE-2013-4338", "CVE-2013-4339", "CVE-2013-4340", "CVE-2013-5738", "CVE-2013-5739");
  script_bugtraq_id(62344, 62345, 62346);
  script_osvdb_id(97210, 97211, 97212, 97213, 97214);
  script_xref(name:"DSA", value:"2757");

  script_name(english:"Debian DSA-2757-1 : wordpress - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were identified in Wordpress, a web blogging
tool. As the CVEs were allocated from releases announcements and
specific fixes are usually not identified, it has been decided to
upgrade the Wordpress package to the latest upstream version instead
of backporting the patches.

This means extra care should be taken when upgrading, especially when
using third-party plugins or themes, since compatibility may have been
impacted along the way. We recommend that users check their install
before doing the upgrade.

  - CVE-2013-4338
    Unsafe PHP unserialization in wp-includes/functions.php
    could cause arbitrary code execution.

  - CVE-2013-4339
    Insufficient input validation could result in
    redirecting or leading a user to another website.

  - CVE-2013-4340
    Privilege escalation allowing an user with an author
    role to create an entry appearing as written by another
    user.

  - CVE-2013-5738
    Insufficient capabilities were required for uploading
    .html/.html files, making it easier for authenticated
    users to conduct cross-site scripting attacks (XSS)
    using crafted html file uploads.

  - CVE-2013-5739
    Default Wordpress configuration allowed file upload for
    .swf/.exe files, making it easier for authenticated
    users to conduct cross-site scripting attacks (XSS)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=722537"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4339"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-5738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-5739"
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
    value:"http://www.debian.org/security/2013/dsa-2757"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wordpress packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 3.6.1+dfsg-1~deb6u1.

For the stable distribution (wheezy), these problems have been fixed
in version 3.6.1+dfsg-1~deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/15");
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
if (deb_check(release:"6.0", prefix:"wordpress", reference:"3.6.1+dfsg-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"wordpress-l10n", reference:"3.6.1+dfsg-1~deb6u1")) flag++;
if (deb_check(release:"7.0", prefix:"wordpress", reference:"3.6.1+dfsg-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wordpress-l10n", reference:"3.6.1+dfsg-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
