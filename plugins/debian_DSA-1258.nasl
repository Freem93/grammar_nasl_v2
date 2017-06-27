#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1258. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24297);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/05 14:49:55 $");

  script_cve_id("CVE-2006-6497", "CVE-2006-6498", "CVE-2006-6499", "CVE-2006-6501", "CVE-2006-6502", "CVE-2006-6503");
  script_bugtraq_id(21668);
  script_osvdb_id(31342, 31343, 31344, 31346, 31347, 31348);
  script_xref(name:"CERT", value:"263412");
  script_xref(name:"CERT", value:"405092");
  script_xref(name:"CERT", value:"427972");
  script_xref(name:"CERT", value:"428500");
  script_xref(name:"CERT", value:"447772");
  script_xref(name:"CERT", value:"606260");
  script_xref(name:"DSA", value:"1258");

  script_name(english:"Debian DSA-1258-1 : mozilla-thunderbird - several vulnerabilities");
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

  - CVE-2006-6497
    Several vulnerabilities in the layout engine allow
    remote attackers to cause a denial of service and
    possibly permit them to execute arbitrary code. [MFSA
    2006-68]

  - CVE-2006-6498
    Several vulnerabilities in the JavaScript engine allow
    remote attackers to cause a denial of service and
    possibly permit them to execute arbitrary code. [MFSA
    2006-68]

  - CVE-2006-6499
    A bug in the js_dtoa function allows remote attackers to
    cause a denial of service. [MFSA 2006-68]

  - CVE-2006-6501
    'shutdown' discovered a vulnerability that allows remote
    attackers to gain privileges and install malicious code
    via the watch JavaScript function. [MFSA 2006-70]

  - CVE-2006-6502
    Steven Michaud discovered a programming bug that allows
    remote attackers to cause a denial of service. [MFSA
    2006-71]

  - CVE-2006-6503
    'moz_bug_r_a4' reported that the src attribute of an IMG
    element could be used to inject JavaScript code. [MFSA
    2006-72]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6499"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6501"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6502"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1258"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Mozilla Thunderbird and Icedove packages.

For the stable distribution (sarge) these problems have been fixed in
version 1.0.2-2.sarge1.0.8e.2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/09");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"mozilla-thunderbird", reference:"1.0.2-2.sarge1.0.8e.2")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-thunderbird-dev", reference:"1.0.2-2.sarge1.0.8e.2")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-thunderbird-inspector", reference:"1.0.2-2.sarge1.0.8e.2")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-thunderbird-offline", reference:"1.0.2-2.sarge1.0.8e.2")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-thunderbird-typeaheadfind", reference:"1.0.2-2.sarge1.0.8e.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
