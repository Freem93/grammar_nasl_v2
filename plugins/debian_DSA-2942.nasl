#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2942. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74278);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/08/15 14:21:39 $");

  script_bugtraq_id(67623, 67624, 67625, 67626, 67627, 67629, 67630);
  script_osvdb_id(107330);
  script_xref(name:"DSA", value:"2942");

  script_name(english:"Debian DSA-2942-1 : typo3-src - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues have been discovered in the Typo3 CMS. More
information can be found in the upstream advisory:
http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-co
re-sa-2014-001/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=749215"
  );
  # http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2014-001/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?48b8b118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/typo3-src"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2942"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the typo3-src packages.

For the stable distribution (wheezy), this problem has been fixed in
version 4.5.19+dfsg1-5+wheezy3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:typo3-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"typo3", reference:"4.5.19+dfsg1-5+wheezy3")) flag++;
if (deb_check(release:"7.0", prefix:"typo3-database", reference:"4.5.19+dfsg1-5+wheezy3")) flag++;
if (deb_check(release:"7.0", prefix:"typo3-dummy", reference:"4.5.19+dfsg1-5+wheezy3")) flag++;
if (deb_check(release:"7.0", prefix:"typo3-src-4.5", reference:"4.5.19+dfsg1-5+wheezy3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
