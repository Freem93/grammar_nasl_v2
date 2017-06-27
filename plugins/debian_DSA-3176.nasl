#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3176. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81556);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/03/11 13:51:32 $");

  script_cve_id("CVE-2014-9472", "CVE-2015-1165", "CVE-2015-1464");
  script_xref(name:"DSA", value:"3176");

  script_name(english:"Debian DSA-3176-1 : request-tracker4 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in Request Tracker, an
extensible trouble-ticket tracking system. The Common Vulnerabilities
and Exposures project identifies the following problems :

  - CVE-2014-9472
    Christian Loos discovered a remote denial of service
    vulnerability, exploitable via the email gateway and
    affecting any installation which accepts mail from
    untrusted sources. Depending on RT's logging
    configuration, a remote attacker can take advantage of
    this flaw to cause CPU and excessive disk usage.

  - CVE-2015-1165
    Christian Loos discovered an information disclosure flaw
    which may reveal RSS feeds URLs, and thus ticket data.

  - CVE-2015-1464
    It was discovered that RSS feed URLs can be leveraged to
    perform session hijacking, allowing a user with the URL
    to log in as the user that created the feed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/request-tracker4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3176"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the request-tracker4 packages.

For the stable distribution (wheezy), these problems have been fixed
in version 4.0.7-5+deb7u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:request-tracker4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"request-tracker4", reference:"4.0.7-5+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"rt4-apache2", reference:"4.0.7-5+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"rt4-clients", reference:"4.0.7-5+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"rt4-db-mysql", reference:"4.0.7-5+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"rt4-db-postgresql", reference:"4.0.7-5+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"rt4-db-sqlite", reference:"4.0.7-5+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"rt4-fcgi", reference:"4.0.7-5+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
