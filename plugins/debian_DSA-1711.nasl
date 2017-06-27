#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1711. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35463);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2009-0255", "CVE-2009-0256", "CVE-2009-0257", "CVE-2009-0258");
  script_bugtraq_id(33376);
  script_osvdb_id(53541, 53542, 53543, 53544);
  script_xref(name:"DSA", value:"1711");

  script_name(english:"Debian DSA-1711-1 : typo3-src - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remotely exploitable vulnerabilities have been discovered in
the TYPO3 web content management framework. The Common Vulnerabilities
and Exposures project identifies the following problems :

  - CVE-2009-0255
    Chris John Riley discovered that the TYPO3-wide used
    encryption key is generated with an insufficiently
    random seed resulting in low entropy which makes it
    easier for attackers to crack this key.

  - CVE-2009-0256
    Marcus Krause discovered that TYPO3 is not invalidating
    a supplied session on authentication which allows an
    attacker to take over a victims session via a session
    fixation attack.

  - CVE-2009-0257
    Multiple cross-site scripting vulnerabilities allow
    remote attackers to inject arbitrary web script or HTML
    via various arguments and user-supplied strings used in
    the indexed search system extension, adodb extension
    test scripts or the workspace module.

  - CVE-2009-0258
    Mads Olesen discovered a remote command injection
    vulnerability in the indexed search system extension
    which allows attackers to execute arbitrary code via a
    crafted file name which is passed unescaped to various
    system tools that extract file content for the indexing.

Because of CVE-2009-0255, please make sure that besides installing
this update, you also create a new encryption key after the
installation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=512608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1711"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the TYPO3 packages.

For the stable distribution (etch) these problems have been fixed in
version 4.0.2+debian-7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 79, 287, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:typo3-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"typo3", reference:"4.0.2+debian-7")) flag++;
if (deb_check(release:"4.0", prefix:"typo3-src-4.0", reference:"4.0.2+debian-7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
