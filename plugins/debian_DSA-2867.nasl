#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2867. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72655);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/16 15:43:10 $");

  script_cve_id("CVE-2014-1471", "CVE-2014-1694");
  script_bugtraq_id(65217, 65241);
  script_osvdb_id(102632, 102661);
  script_xref(name:"DSA", value:"2867");

  script_name(english:"Debian DSA-2867-1 : otrs2 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in otrs2, the Open Ticket
Request System. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2014-1694
    Norihiro Tanaka reported missing challenge token checks.
    An attacker that managed to take over the session of a
    logged in customer could create tickets and/or send
    follow-ups to existing tickets due to these missing
    checks.

  - CVE-2014-1471
    Karsten Nielsen from Vasgard GmbH discovered that an
    attacker with a valid customer or agent login could
    inject SQL code through the ticket search URL."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-1694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-1471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/otrs2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/otrs2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2867"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the otrs2 packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 2.4.9+dfsg1-3+squeeze5.

For the stable distribution (wheezy), these problems have been fixed
in version 3.1.7+dfsg1-8+deb7u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:otrs2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/24");
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
if (deb_check(release:"6.0", prefix:"otrs2", reference:"2.4.9+dfsg1-3+squeeze5")) flag++;
if (deb_check(release:"7.0", prefix:"otrs", reference:"3.1.7+dfsg1-8+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"otrs2", reference:"3.1.7+dfsg1-8+deb7u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
