#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-813-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(96930);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/02/13 20:45:09 $");

  script_cve_id("CVE-2017-5488", "CVE-2017-5489", "CVE-2017-5490", "CVE-2017-5491", "CVE-2017-5492", "CVE-2017-5493", "CVE-2017-5610", "CVE-2017-5611", "CVE-2017-5612");
  script_osvdb_id(149964, 149965, 149966, 149967, 149968, 149969, 151030, 151031, 151032);

  script_name(english:"Debian DLA-813-1 : wordpress security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in wordpress, a web blogging
tool. The Common Vulnerabilities and Exposures project identifies the
following issues.

CVE-2017-5488

Multiple cross-site scripting (XSS) vulnerabilities in
wp-admin/update-core.php in WordPress before 4.7.1 allow remote
attackers to inject arbitrary web script or HTML via the name or
version header of a plugin.

CVE-2017-5489

Cross-site request forgery (CSRF) vulnerability in WordPress before
4.7.1 allows remote attackers to hijack the authentication of
unspecified victims via vectors involving a Flash file upload.

CVE-2017-5490

Cross-site scripting (XSS) vulnerability in the theme-name fallback
functionality in wp-includes/class-wp-theme.php in WordPress before
4.7.1 allows remote attackers to inject arbitrary web script or HTML
via a crafted directory name of a theme, related to
wp-admin/includes/class-theme-installer-skin.php.

CVE-2017-5491

wp-mail.php in WordPress before 4.7.1 might allow remote attackers to
bypass intended posting restrictions via a spoofed mail server with
the mail.example.com name.

CVE-2017-5492

Cross-site request forgery (CSRF) vulnerability in the widget-editing
accessibility-mode feature in WordPress before 4.7.1 allows remote
attackers to hijack the authentication of unspecified victims for
requests that perform a widgets-access action, related to
wp-admin/includes/class-wp-screen.php and wp-admin/widgets.php.

CVE-2017-5493

wp-includes/ms-functions.php in the Multisite WordPress API in
WordPress before 4.7.1 does not properly choose random numbers for
keys, which makes it easier for remote attackers to bypass intended
access restrictions via a crafted site signup or user signup.

CVE-2017-5610

wp-admin/includes/class-wp-press-this.php in Press This in WordPress
before 4.7.2 does not properly restrict visibility of a
taxonomy-assignment user interface, which allows remote attackers to
bypass intended access restrictions by reading terms.

CVE-2017-5611

SQL injection vulnerability in wp-includes/class-wp-query.php in
WP_Query in WordPress before 4.7.2 allows remote attackers to execute
arbitrary SQL commands by leveraging the presence of an affected
plugin or theme that mishandles a crafted post type name.

CVE-2017-5612

Cross-site scripting (XSS) vulnerability in
wp-admin/includes/class-wp-posts-list-table.php in the posts list
table in WordPress before 4.7.2 allows remote attackers to inject
arbitrary web script or HTML via a crafted excerpt.

For Debian 7 'Wheezy', these problems have been fixed in version
3.6.1+dfsg-1~deb7u13.

We recommend that you upgrade your wordpress packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/02/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/wordpress"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected wordpress, and wordpress-l10n packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-l10n");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"wordpress", reference:"3.6.1+dfsg-1~deb7u13")) flag++;
if (deb_check(release:"7.0", prefix:"wordpress-l10n", reference:"3.6.1+dfsg-1~deb7u13")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
