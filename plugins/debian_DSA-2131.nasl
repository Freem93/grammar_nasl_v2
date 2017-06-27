#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2131. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51128);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/05/03 11:20:11 $");

  script_cve_id("CVE-2010-4344");
  script_osvdb_id(69685);
  script_xref(name:"DSA", value:"2131");

  script_name(english:"Debian DSA-2131-1 : exim4 - arbitrary code execution");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been found in exim4 that allow a remote
attacker to execute arbitrary code as root user. Exploits for these
issues have been seen in the wild.

This update fixes a memory corruption issue that allows a remote
attacker to execute arbitrary code as the Debian-exim user
(CVE-2010-4344 ).

A fix for an additional issue that allows the Debian-exim user to
obtain root privileges (CVE-2010-4345 ) is currently being checked for
compatibility issues. It is not yet included in this upgrade but will
released soon in an update to this advisory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2131"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the exim4 packages.

For the stable distribution (lenny), this problem has been fixed in
version 4.69-9+lenny1.

This advisory only contains the packages for the alpha, amd64, hppa,
i386, ia64, powerpc, and s390 architectures. The packages for the arm,
armel, mips, mipsel, and sparc architectures will be released as soon
as they are built."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim4 string_format Function Heap Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/12");
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
if (deb_check(release:"5.0", prefix:"exim4", reference:"4.69-9+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"exim4-base", reference:"4.69-9+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"exim4-config", reference:"4.69-9+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"exim4-daemon-heavy", reference:"4.69-9+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"exim4-daemon-heavy-dbg", reference:"4.69-9+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"exim4-daemon-light", reference:"4.69-9+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"exim4-daemon-light-dbg", reference:"4.69-9+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"exim4-dbg", reference:"4.69-9+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"exim4-dev", reference:"4.69-9+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"eximon4", reference:"4.69-9+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
