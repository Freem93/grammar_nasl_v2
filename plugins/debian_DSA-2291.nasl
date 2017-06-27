#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2291. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55776);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2010-4554", "CVE-2010-4555", "CVE-2011-2023", "CVE-2011-2752", "CVE-2011-2753");
  script_bugtraq_id(48648);
  script_osvdb_id(74083, 74084, 74085, 74086, 74087, 74088, 74089);
  script_xref(name:"DSA", value:"2291");

  script_name(english:"Debian DSA-2291-1 : squirrelmail - various vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Various vulnerabilities have been found in SquirrelMail, a webmail
application. The Common Vulnerabilities and Exposures project
identifies the following vulnerabilities :

  - CVE-2010-4554
    SquirrelMail did not prevent page rendering inside a
    third-party HTML frame, which makes it easier for remote
    attackers to conduct clickjacking attacks via a crafted
    website.

  - CVE-2010-4555, CVE-2011-2752, CVE-2011-2753
    Multiple small bugs in SquirrelMail allowed an attacker
    to inject malicious script into various pages or alter
    the contents of user preferences.

  - CVE-2011-2023
    It was possible to inject arbitrary web script or HTML
    via a crafted STYLE element in an HTML part of an e-mail
    message."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4554"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2753"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/squirrelmail"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2291"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the squirrelmail packages.

For the oldstable distribution (lenny), these problems have been fixed
in version 1.4.15-4+lenny5.

For the stable distribution (squeeze), these problems have been fixed
in version 1.4.21-2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squirrelmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/09");
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
if (deb_check(release:"5.0", prefix:"squirrelmail", reference:"1.4.15-4+lenny5")) flag++;
if (deb_check(release:"6.0", prefix:"squirrelmail", reference:"1.4.21-2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
