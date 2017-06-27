#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2733. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69197);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:43:09 $");

  script_cve_id("CVE-2013-4717");
  script_bugtraq_id(61037);
  script_osvdb_id(85074, 92087, 94436, 95015);
  script_xref(name:"DSA", value:"2733");

  script_name(english:"Debian DSA-2733-1 : otrs2 - SQL injection");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that otrs2, the Open Ticket Request System, does not
properly sanitise user-supplied data that is used on SQL queries. An
attacker with a valid agent login could exploit this issue to craft
SQL queries by injecting arbitrary SQL code through manipulated URLs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-4751"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4088"
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
    value:"http://www.debian.org/security/2013/dsa-2733"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the otrs2 packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 2.4.9+dfsg1-3+squeeze4. This update also provides fixes for
CVE-2012-4751, CVE-2013-2625 and CVE-2013-4088, which were all fixed
for stable already.

For the stable distribution (wheezy), this problem has been fixed in
version 3.1.7+dfsg1-8+deb7u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:otrs2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/05");
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
if (deb_check(release:"6.0", prefix:"otrs2", reference:"2.4.9+dfsg1-3+squeeze4")) flag++;
if (deb_check(release:"7.0", prefix:"otrs", reference:"3.1.7+dfsg1-8+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"otrs2", reference:"3.1.7+dfsg1-8+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
