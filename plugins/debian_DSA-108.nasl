#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-108. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14945);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/17 23:36:52 $");

  script_cve_id("CVE-2002-0247", "CVE-2002-0248");
  script_osvdb_id(12329);
  script_xref(name:"DSA", value:"108");

  script_name(english:"Debian DSA-108-1 : wmtv - symlink vulnerability");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Nicolas Boullis found some security problems in the wmtv package (a
dockable video4linux TV player for windowmaker) which is distributed
in Debian GNU/Linux 2.2. With the current version of wmtv, the
configuration file is written back as the superuser, and without any
further checks. A malicious user might use that to damage important
files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-108"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wmtv packages immediately.

This problem has been fixed in version 0.6.5-2potato2 for the stable
distribution by dropping privileges as soon as possible and only
regaining them where required. In the current testing/unstable
distribution this problem has been fixed in version 0.6.5-9 and above
by not requiring privileges anymore. Both contain fixes for two
potential buffer overflows as well."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wmtv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/02/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"wmtv", reference:"0.6.5-2potato2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
