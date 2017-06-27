#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1210. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(23659);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2006-2788", "CVE-2006-4340", "CVE-2006-4565", "CVE-2006-4566", "CVE-2006-4568", "CVE-2006-4571");
  script_bugtraq_id(20042);
  script_osvdb_id(27668, 28843, 28844, 28846, 28848, 29013, 94476, 94477, 94478, 94479, 94480, 95338, 95339, 95340, 95341, 95911, 95912, 95913, 95914, 95915, 96645);
  script_xref(name:"DSA", value:"1210");

  script_name(english:"Debian DSA-1210-1 : mozilla-firefox - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security related problems have been discovered in Mozilla and
derived products such as Mozilla Firefox. The Common Vulnerabilities
and Exposures project identifies the following vulnerabilities :

  - CVE-2006-2788
    Fernando Ribeiro discovered that a vulnerability in the
    getRawDER function allows remote attackers to cause a
    denial of service (hang) and possibly execute arbitrary
    code.

  - CVE-2006-4340
    Daniel Bleichenbacher recently described an
    implementation error in RSA signature verification that
    cause the application to incorrectly trust SSL
    certificates.

  - CVE-2006-4565, CVE-2006-4566
    Priit Laes reported that a JavaScript regular expression
    can trigger a heap-based buffer overflow which allows
    remote attackers to cause a denial of service and
    possibly execute arbitrary code.

  - CVE-2006-4568
    A vulnerability has been discovered that allows remote
    attackers to bypass the security model and inject
    content into the sub-frame of another site.

  - CVE-2006-4571
    Multiple unspecified vulnerabilities in Firefox,
    Thunderbird and SeaMonkey allow remote attackers to
    cause a denial of service, corrupt memory, and possibly
    execute arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4568"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4571"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1210"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Mozilla Firefox packages.

For the stable distribution (sarge) these problems have been fixed in
version 1.0.4-2sarge12."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 79, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/20");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"mozilla-firefox", reference:"1.0.4-2sarge12")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-firefox-dom-inspector", reference:"1.0.4-2sarge12")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-firefox-gnome-support", reference:"1.0.4-2sarge12")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
