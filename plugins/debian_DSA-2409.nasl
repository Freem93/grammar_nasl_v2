#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2409. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57963);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/01/14 15:20:31 $");

  script_cve_id("CVE-2012-0210", "CVE-2012-0211", "CVE-2012-0212");
  script_osvdb_id(79319, 79320, 79321);
  script_xref(name:"DSA", value:"2409");

  script_name(english:"Debian DSA-2409-1 : devscripts - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in debdiff, a script used
to compare two Debian packages, which is part of the devscripts
package. The following Common Vulnerabilities and Exposures project
ids have been assigned to identify them :

  - CVE-2012-0210 :
    Paul Wise discovered that due to insufficient input
    sanitising when processing .dsc and .changes files, it
    is possible to execute arbitrary code and disclose
    system information.

  - CVE-2012-0211 :
    Raphael Geissert discovered that it is possible to
    inject or modify arguments of external commands when
    processing source packages with specially-named tarballs
    in the top-level directory of the .orig tarball,
    allowing arbitrary code execution.

  - CVE-2012-0212 :
    Raphael Geissert discovered that it is possible to
    inject or modify arguments of external commands when
    passing as argument to debdiff a specially-named file,
    allowing arbitrary code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0210"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0212"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/devscripts"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2409"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the devscripts packages.

For the stable distribution (squeeze), these problems have been fixed
in version 2.10.69+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:devscripts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/16");
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
if (deb_check(release:"6.0", prefix:"devscripts", reference:"2.10.69+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
