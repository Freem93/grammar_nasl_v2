#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2121. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50024);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2010-3714", "CVE-2010-3715", "CVE-2010-3716", "CVE-2010-3717");
  script_bugtraq_id(43786);
  script_osvdb_id(68590, 68591, 68592, 69218, 69219);
  script_xref(name:"DSA", value:"2121");

  script_name(english:"Debian DSA-2121-1 : typo3-src - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in TYPO3. The
Common Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2010-3714
    Multiple remote file disclosure vulnerabilities in the
    jumpUrl mechanism and the Extension Manager allowed
    attackers to read files with the privileges of the
    account under which the web server was running.

  - CVE-2010-3715
    The TYPO3 backend contained several cross-site scripting
    vulnerabilities, and the RemoveXSS function did not
    filter all JavaScript code.

  - CVE-2010-3716
    Malicious editors with user creation permission could
    escalate their privileges by creating new users in
    arbitrary groups, due to lack of input validation in the
    taskcenter.

  - CVE-2010-3717
    TYPO3 exposed a crasher bug in the PHP filter_var
    function, enabling attackers to cause the web server
    process to crash and thus consume additional system
    resources."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3714"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3716"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2121"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the TYPO3 packages.

For the stable distribution (lenny), these problems have been fixed in
version 4.2.5-1+lenny6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:typo3-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");
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
if (deb_check(release:"5.0", prefix:"typo3", reference:"4.2.5-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"typo3-src-4.2", reference:"4.2.5-1+lenny6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
