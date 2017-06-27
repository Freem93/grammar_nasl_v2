#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2574. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62929);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:37:39 $");

  script_cve_id("CVE-2012-6144", "CVE-2012-6145", "CVE-2012-6146", "CVE-2012-6147");
  script_bugtraq_id(56472);
  script_osvdb_id(87112, 87113, 87114, 87115, 87116);
  script_xref(name:"DSA", value:"2574");

  script_name(english:"Debian DSA-2574-1 : typo3-src - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in TYPO3, a content management
system. This update addresses cross-site scripting, SQL injection, and
information disclosure vulnerabilities and corresponds to
TYPO3-CORE-SA-2012-005."
  );
  # http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2012-005/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a8e68ecf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/typo3-src"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2574"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the typo3-src packages.

For the stable distribution (squeeze), this problem has been fixed in
version 4.3.9+dfsg1-1+squeeze7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:typo3-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"typo3", reference:"4.3.9+dfsg1-1+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"typo3-database", reference:"4.3.9+dfsg1-1+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"typo3-src-4.3", reference:"4.3.9+dfsg1-1+squeeze7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
