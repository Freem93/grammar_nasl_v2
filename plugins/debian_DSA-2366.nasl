#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2366. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57506);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2011-1578", "CVE-2011-1579", "CVE-2011-1580", "CVE-2011-1587", "CVE-2011-4360", "CVE-2011-4361");
  script_bugtraq_id(47354, 50844);
  script_osvdb_id(74619, 74620, 74621, 77364, 77365);
  script_xref(name:"DSA", value:"2366");

  script_name(english:"Debian DSA-2366-1 : mediawiki - multiple vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several problems have been discovered in MediaWiki, a website engine
for collaborative work.

  - CVE-2011-1578 CVE-2011-1587
    Masato Kinugawa discovered a cross-site scripting (XSS)
    issue, which affects Internet Explorer clients only, and
    only version 6 and earlier. Web server configuration
    changes are required to fix this issue. Upgrading
    MediaWiki will only be sufficient for people who use
    Apache with AllowOverride enabled.

  For details of the required configuration changes, see the upstream
  announcements.

  - CVE-2011-1579
    Wikipedia user Suffusion of Yellow discovered a CSS
    validation error in the wikitext parser. This is an XSS
    issue for Internet Explorer clients, and a privacy loss
    issue for other clients since it allows the embedding of
    arbitrary remote images.

  - CVE-2011-1580
    MediaWiki developer Happy-Melon discovered that the
    transwiki import feature neglected to perform access
    control checks on form submission. The transwiki import
    feature is disabled by default. If it is enabled, it
    allows wiki pages to be copied from a remote wiki listed
    in $wgImportSources. The issue means that any user can
    trigger such an import to occur.

  - CVE-2011-4360
    Alexandre Emsenhuber discovered an issue where page
    titles on private wikis could be exposed bypassing
    different page ids to index.php. In the case of the user
    not having correct permissions, they will now be
    redirected to Special:BadTitle.

  - CVE-2011-4361
    Tim Starling discovered that action=ajax requests were
    dispatched to the relevant function without any read
    permission checks being done. This could have led to
    data leakage on private wikis."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=650434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1587"
  );
  # http://lists.wikimedia.org/pipermail/mediawiki-announce/2011-April/000096.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ccfd3229"
  );
  # http://lists.wikimedia.org/pipermail/mediawiki-announce/2011-April/000097.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb194760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4361"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/mediawiki"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2366"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mediawiki packages.

For the oldstable distribution (lenny), these problems have been fixed
in version 1:1.12.0-2lenny9.

For the stable distribution (squeeze), these problems have been fixed
in version 1:1.15.5-2squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mediawiki");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"mediawiki", reference:"1:1.12.0-2lenny9")) flag++;
if (deb_check(release:"6.0", prefix:"mediawiki", reference:"1:1.15.5-2squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"mediawiki-math", reference:"1:1.15.5-2squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
