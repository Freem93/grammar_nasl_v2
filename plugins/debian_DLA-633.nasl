#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-633-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93667);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2017/01/23 17:47:51 $");

  script_cve_id("CVE-2015-8834", "CVE-2016-4029", "CVE-2016-5836", "CVE-2016-6634", "CVE-2016-6635", "CVE-2016-7168", "CVE-2016-7169");
  script_osvdb_id(121803, 137859, 137860, 137861, 140313, 143887, 143888);

  script_name(english:"Debian DLA-633-1 : wordpress security update");
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

CVE-2015-8834: Cross-site scripting (XSS) vulnerability in
wp-includes/wp-db.php in WordPress before 4.2.2 allows remote
attackers to inject arbitrary web script or HTML via a long comment
that is improperly stored because of limitations on the MySQL TEXT
data type. NOTE: this vulnerability exists because of an incomplete
fix for CVE-2015-3440

CVE-2016-4029: WordPress before 4.5 does not consider octal and
hexadecimal IP address formats when determining an intranet address,
which allows remote attackers to bypass an intended SSRF protection
mechanism via a crafted address.

CVE-2016-5836: The oEmbed protocol implementation in WordPress before
4.5.3 allows remote attackers to cause a denial of service via
unspecified vectors.

CVE-2016-6634: Cross-site scripting (XSS) vulnerability in the network
settings page in WordPress before 4.5 allows remote attackers to
inject arbitrary web script or HTML via unspecified vectors.

CVE-2016-6635: Cross-site request forgery (CSRF) vulnerability in the
wp_ajax_wp_compression_test function in wp-admin/includes/ajax-
actions.php in WordPress before 4.5 allows remote attackers to hijack
the authentication of administrators for requests that change the
script compression option.

CVE-2016-7168: Fix a cross-site scripting vulnerability via image
filename.

CVE-2016-7169: Fix a path traversal vulnerability in the upgrade
package uploader.

For Debian 7 'Wheezy', these problems have been fixed in version
3.6.1+dfsg-1~deb7u12.

We recommend that you upgrade your wordpress packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/09/msg00026.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/wordpress"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected wordpress, and wordpress-l10n packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-l10n");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"wordpress", reference:"3.6.1+dfsg-1~deb7u12")) flag++;
if (deb_check(release:"7.0", prefix:"wordpress-l10n", reference:"3.6.1+dfsg-1~deb7u12")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
