#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2097. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(48924);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/05/03 11:20:11 $");

  script_cve_id("CVE-2010-3055", "CVE-2010-3056");
  script_bugtraq_id(42591);
  script_osvdb_id(67310, 67316, 67317, 67318, 67319, 67320, 67321, 67322, 67323, 67324, 67325, 67343, 67485, 67486, 67487, 67488, 67489, 67490, 67491);
  script_xref(name:"DSA", value:"2097");

  script_name(english:"Debian DSA-2097-1 : phpmyadmin - insufficient input sanitising");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in phpMyAdmin, a
tool to administer MySQL over the web. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2010-3055
    The configuration setup script does not properly
    sanitise its output file, which allows remote attackers
    to execute arbitrary PHP code via a crafted POST
    request. In Debian, the setup tool is protected through
    Apache HTTP basic authentication by default.

  - CVE-2010-3056
    Various cross site scripting issues have been discovered
    that allow a remote attacker to inject arbitrary web
    script or HTML."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3055"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2097"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the phpmyadmin package.

For the stable distribution (lenny), these problems have been fixed in
version 2.11.8.1-5+lenny5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:phpmyadmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"phpmyadmin", reference:"2.11.8.1-5+lenny5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
