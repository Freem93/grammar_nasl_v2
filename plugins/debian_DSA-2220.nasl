#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2220. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53495);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2011-1685", "CVE-2011-1686", "CVE-2011-1687", "CVE-2011-1688", "CVE-2011-1689", "CVE-2011-1690");
  script_bugtraq_id(47383);
  script_osvdb_id(74793, 74794, 74795, 74796, 74797, 74798);
  script_xref(name:"DSA", value:"2220");

  script_name(english:"Debian DSA-2220-1 : request-tracker3.6, request-tracker3.8 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Request Tracker, an issue
tracking system.

  - CVE-2011-1685
    If the external custom field feature is enabled, Request
    Tracker allows authenticated users to execute arbitrary
    code with the permissions of the web server, possible
    triggered by a cross-site request forgery attack.
    (External custom fields are disabled by default.)

  - CVE-2011-1686
    Multiple SQL injection attacks allow authenticated users
    to obtain data from the database in an unauthorized way.

  - CVE-2011-1687
    An information leak allows an authenticated privileged
    user to obtain sensitive information, such as encrypted
    passwords, via the search interface.

  - CVE-2011-1688
    When running under certain web servers (such as
    Lighttpd), Request Tracker is vulnerable to a directory
    traversal attack, allowing attackers to read any files
    accessible to the web server. Request Tracker instances
    running under Apache or Nginx are not affected.

  - CVE-2011-1689
    Request Tracker contains multiple cross-site scripting
    vulnerabilities.

  - CVE-2011-1690
    Request Tracker enables attackers to redirect
    authentication credentials supplied by legitimate users
    to third-party servers."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/request-tracker3.8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2220"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Request Tracker packages.

For the oldstable distribution (lenny), these problems have been fixed
in version 3.6.7-5+lenny6 of the request-tracker3.6 package.

For the stable distribution (squeeze), these problems have been fixed
in version 3.8.8-7+squeeze1 of the request-tracker3.8 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:request-tracker3.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:request-tracker3.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"request-tracker3.6", reference:"3.6.7-5+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"request-tracker3.8", reference:"3.6.7-5+lenny6")) flag++;
if (deb_check(release:"6.0", prefix:"request-tracker3.6", reference:"3.8.8-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"request-tracker3.8", reference:"3.8.8-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"rt3.8-apache2", reference:"3.8.8-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"rt3.8-clients", reference:"3.8.8-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"rt3.8-db-mysql", reference:"3.8.8-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"rt3.8-db-postgresql", reference:"3.8.8-7+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"rt3.8-db-sqlite", reference:"3.8.8-7+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
