#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2549. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62113);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2012-2240", "CVE-2012-2241", "CVE-2012-2242", "CVE-2012-3500");
  script_bugtraq_id(55358);
  script_osvdb_id(85610, 85611, 85612, 85613);
  script_xref(name:"DSA", value:"2549");

  script_name(english:"Debian DSA-2549-1 : devscripts - multiple vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in devscripts, a set of
scripts to make the life of a Debian Package maintainer easier. The
following Common Vulnerabilities and Exposures project ids have been
assigned to identify them :

  - CVE-2012-2240 :
    Raphael Geissert discovered that dscverify does not
    perform sufficient validation and does not properly
    escape arguments to external commands, allowing a remote
    attacker (as when dscverify is used by dget) to execute
    arbitrary code.

  - CVE-2012-2241 :
    Raphael Geissert discovered that dget allows an attacker
    to delete arbitrary files when processing a specially
    crafted .dsc or .changes file, due to insuficient input
    validation.

  - CVE-2012-2242 :
    Raphael Geissert discovered that dget does not properly
    escape arguments to external commands when processing
    .dsc and .changes files, allowing an attacker to execute
    arbitrary code. This issue is limited with the fix for
    CVE-2012-2241, and had already been fixed in version
    2.10.73 due to changes to the code, without considering
    its security implications.

  - CVE-2012-3500 :
    Jim Meyering, Red Hat, discovered that annotate-output
    determines the name of temporary named pipes in a way
    that allows a local attacker to make it abort, leading
    to denial of service.

Additionally, a regression in the exit code of debdiff introduced in
DSA-2409-1 has been fixed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-2240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-2241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-2242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-2241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/devscripts"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2549"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the devscripts packages.

For the stable distribution (squeeze), these problems have been fixed
in version 2.10.69+squeeze4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:devscripts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"devscripts", reference:"2.10.69+squeeze4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
