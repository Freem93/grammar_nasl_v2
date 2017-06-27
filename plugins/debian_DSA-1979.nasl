#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1979. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44843);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2009-4013", "CVE-2009-4014", "CVE-2009-4015");
  script_osvdb_id(62125, 62126, 62127);
  script_xref(name:"DSA", value:"1979");

  script_name(english:"Debian DSA-1979-1 : lintian - multiple vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in lintian, a Debian
package checker. The following Common Vulnerabilities and Exposures
project ids have been assigned to identify them :

  - CVE-2009-4013: missing control files sanitation
    Control field names and values were not sanitised before
    using them in certain operations that could lead to
    directory traversals.

  Patch systems' control files were not sanitised before using them in
  certain operations that could lead to directory traversals.

  An attacker could exploit these vulnerabilities to overwrite
  arbitrary files or disclose system information.

  - CVE-2009-4014: format string vulnerabilities
    Multiple check scripts and the Lintian::Schedule module
    were using user-provided input as part of the
    sprintf/printf format string.

  - CVE-2009-4015: arbitrary command execution
    File names were not properly escaped when passing them
    as arguments to certain commands, allowing the execution
    of other commands as pipes or as a set of shell
    commands."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-1979"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the lintian packages.

For the oldstable distribution (etch), these problems have been fixed
in version 1.23.28+etch1.

For the stable distribution (lenny), these problems have been fixed in
version 1.24.2.1+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(22, 89, 134);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lintian");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"lintian", reference:"1.23.28+etch1")) flag++;
if (deb_check(release:"5.0", prefix:"lintian", reference:"1.24.2.1+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
