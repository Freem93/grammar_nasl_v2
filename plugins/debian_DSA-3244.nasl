#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3244. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83193);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/04/28 18:23:49 $");

  script_cve_id("CVE-2015-3011", "CVE-2015-3012", "CVE-2015-3013");
  script_osvdb_id(119587, 120034, 120035, 121827, 121828);
  script_xref(name:"DSA", value:"3244");

  script_name(english:"Debian DSA-3244-1 : owncloud - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in ownCloud, a cloud storage
web service for files, music, contacts, calendars and many more.

  - CVE-2015-3011
    Hugh Davenport discovered that the 'contacts'
    application shipped with ownCloud is vulnerable to
    multiple stored cross-site scripting attacks. This
    vulnerability is effectively exploitable in any browser.

  - CVE-2015-3012
    Roy Jansen discovered that the 'documents' application
    shipped with ownCloud is vulnerable to multiple stored
    cross-site scripting attacks. This vulnerability is not
    exploitable in browsers that support the current CSP
    standard.

  - CVE-2015-3013
    Lukas Reschke discovered a blacklist bypass
    vulnerability, allowing authenticated remote attackers
    to bypass the file blacklist and upload files such as
    the .htaccess files. An attacker could leverage this
    bypass by uploading a .htaccess and execute arbitrary
    PHP code if the /data/ directory is stored inside the
    web root and a web server that interprets .htaccess
    files is used. On default Debian installations the data
    directory is outside of the web root and thus this
    vulnerability is not exploitable by default."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/owncloud"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3244"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the owncloud packages.

For the stable distribution (jessie), these problems have been fixed
in version 7.0.4+dfsg-4~deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:owncloud");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/04");
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
if (deb_check(release:"8.0", prefix:"owncloud", reference:"7.0.4+dfsg-4~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
