#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2470. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59093);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/04/07 13:27:20 $");

  script_cve_id("CVE-2011-3122", "CVE-2011-3125", "CVE-2011-3126", "CVE-2011-3127", "CVE-2011-3128", "CVE-2011-3129", "CVE-2011-3130", "CVE-2011-4956", "CVE-2011-4957", "CVE-2012-2399", "CVE-2012-2400", "CVE-2012-2401", "CVE-2012-2402", "CVE-2012-2403", "CVE-2012-2404");
  script_bugtraq_id(73868);
  script_osvdb_id(72141, 72142, 74485, 74486, 74487, 74488, 74489, 74490, 74491, 81459, 81460, 81461, 81462, 81463, 81464);
  script_xref(name:"DSA", value:"2470");

  script_name(english:"Debian DSA-2470-1 : wordpress - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were identified in WordPress, a web blogging
tool. As the CVEs were allocated from releases announcements and
specific fixes are usually not identified, it has been decided to
upgrade the wordpress package to the latest upstream version instead
of backporting the patches.

This means extra care should be taken when upgrading, especially when
using third-party plugins or themes, since compatibility may have been
impacted along the way. We recommend that users check their install
before doing the upgrade."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=670124"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/wordpress"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2470"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wordpress packages.

For the stable distribution (squeeze), those problems have been fixed
in version 3.3.2+dfsg-1~squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/15");
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
if (deb_check(release:"6.0", prefix:"wordpress", reference:"3.3.2+dfsg-1~squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"wordpress-l10n", reference:"3.3.2+dfsg-1~squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
