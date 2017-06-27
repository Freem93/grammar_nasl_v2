#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2098. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(48925);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/19 14:44:44 $");

  script_bugtraq_id(42029);
  script_osvdb_id(66864, 66865, 66866, 66867, 66868, 66869, 66870, 66871, 66872, 66873, 66874, 66875, 66876, 66877, 66878, 66879, 66880);
  script_xref(name:"DSA", value:"2098");

  script_name(english:"Debian DSA-2098-1 : typo3-src - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in the TYPO3 web
content management framework: cross-site Scripting, open redirection,
SQL injection, broken authentication and session management, insecure
randomness, information disclosure and arbitrary code execution. More
details can be found in the Typo3 security advisory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=590719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://typo3.org/teams/security/security-bulletins/typo3-sa-2010-012/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2098"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the typo3-src package.

For the stable distribution (lenny), these problems have been fixed in
version 4.2.5-1+lenny4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:typo3-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"typo3", reference:"4.2.5-1+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"typo3-src-4.2", reference:"4.2.5-1+lenny4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
