#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2718. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67131);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/02/16 15:43:09 $");

  script_cve_id("CVE-2013-2173", "CVE-2013-2199", "CVE-2013-2200", "CVE-2013-2201", "CVE-2013-2202", "CVE-2013-2203", "CVE-2013-2204", "CVE-2013-2205");
  script_bugtraq_id(60477, 60757, 60758, 60759, 60770, 60775, 60781, 60825);
  script_osvdb_id(94235, 94783, 94784, 94785, 94786, 94787, 94788, 94789, 94790, 94791);
  script_xref(name:"DSA", value:"2718");

  script_name(english:"Debian DSA-2718-1 : wordpress - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were identified in WordPress, a web blogging
tool. As the CVEs were allocated from releases announcements and
specific fixes are usually not identified, it has been decided to
upgrade the wordpress package to the latest upstream version instead
of backporting the patches.

This means extra care should be taken when upgrading, especially when
using third-party plugins or themes, since compatibility may have been
impacted along the way. We recommend that users check their install
before doing the upgrade.

  - CVE-2013-2173
    A denial of service was found in the way WordPress
    performs hash computation when checking password for
    protected posts. An attacker supplying carefully crafted
    input as a password could make the platform use
    excessive CPU usage.

  - CVE-2013-2199
    Multiple server-side requests forgery (SSRF)
    vulnerabilities were found in the HTTP API. This is
    related to CVE-2013-0235, which was specific to SSRF in
    pingback requests and was fixed in 3.5.1.

  - CVE-2013-2200
    Inadequate checking of a user's capabilities could lead
    to a privilege escalation, enabling them to publish
    posts when their user role should not allow for it and
    to assign posts to other authors.

  - CVE-2013-2201
    Multiple cross-side scripting (XSS) vulnerabilities due
    to badly escaped input were found in the media files and
    plugins upload forms.

  - CVE-2013-2202
    XML External Entity Injection (XXE) vulnerability via
    oEmbed responses.

  - CVE-2013-2203
    A Full path disclosure (FPD) was found in the file
    upload mechanism. If the upload directory is not
    writable, the error message returned includes the full
    directory path.

  - CVE-2013-2204
    Content spoofing via Flash applet in the embedded
    tinyMCE media plugin.

  - CVE-2013-2205
    Cross-domain XSS in the embedded SWFupload uploader."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=713947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-0235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2203"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2205"
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
    value:"http://www.debian.org/security/2013/dsa-2718"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wordpress packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 3.5.2+dfsg-1~deb6u1.

For the stable distribution (wheezy), these problems have been fixed
in version 3.5.2+dfsg-1~deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/03");
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
if (deb_check(release:"6.0", prefix:"wordpress", reference:"3.5.2+dfsg-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"wordpress-l10n", reference:"3.5.2+dfsg-1~deb6u1")) flag++;
if (deb_check(release:"7.0", prefix:"wordpress", reference:"3.5.2+dfsg-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wordpress-l10n", reference:"3.5.2+dfsg-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
