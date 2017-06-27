#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1696. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(35313);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-0016", "CVE-2008-1380", "CVE-2008-3835", "CVE-2008-4058", "CVE-2008-4059", "CVE-2008-4060", "CVE-2008-4061", "CVE-2008-4062", "CVE-2008-4065", "CVE-2008-4067", "CVE-2008-4068", "CVE-2008-4070", "CVE-2008-4582", "CVE-2008-5012", "CVE-2008-5014", "CVE-2008-5017", "CVE-2008-5018", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5024", "CVE-2008-5500", "CVE-2008-5503", "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5511", "CVE-2008-5512");
  script_bugtraq_id(28818, 31346, 31397, 31411, 32281, 32882);
  script_osvdb_id(44467, 48780);
  script_xref(name:"DSA", value:"1696");

  script_name(english:"Debian DSA-1696-1 : icedove - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in the Icedove
mail client, an unbranded version of the Thunderbird mail client. The
Common Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2008-0016
    Justin Schuh, Tom Cross and Peter Williams discovered a
    buffer overflow in the parser for UTF-8 URLs, which may
    lead to the execution of arbitrary code. (MFSA 2008-37)

  - CVE-2008-1380
    It was discovered that crashes in the JavaScript engine
    could potentially lead to the execution of arbitrary
    code. (MFSA 2008-20)

  - CVE-2008-3835
    'moz_bug_r_a4' discovered that the same-origin check in
    nsXMLDocument::OnChannelRedirect() could be bypassed.
    (MFSA 2008-38)

  - CVE-2008-4058
    'moz_bug_r_a4' discovered a vulnerability which can
    result in Chrome privilege escalation through
    XPCNativeWrappers. (MFSA 2008-41)

  - CVE-2008-4059
    'moz_bug_r_a4' discovered a vulnerability which can
    result in Chrome privilege escalation through
    XPCNativeWrappers. (MFSA 2008-41)

  - CVE-2008-4060
    Olli Pettay and 'moz_bug_r_a4' discovered a Chrome
    privilege escalation vulnerability in XSLT handling.
    (MFSA 2008-41)

  - CVE-2008-4061
    Jesse Ruderman discovered a crash in the layout engine,
    which might allow the execution of arbitrary code. (MFSA
    2008-42)

  - CVE-2008-4062
    Igor Bukanov, Philip Taylor, Georgi Guninski and Antoine
    Labour discovered crashes in the JavaScript engine,
    which might allow the execution of arbitrary code. (MFSA
    2008-42)

  - CVE-2008-4065
    Dave Reed discovered that some Unicode byte order marks
    are stripped from JavaScript code before execution,
    which can result in code being executed, which were
    otherwise part of a quoted string. (MFSA 2008-43)

  - CVE-2008-4067
    It was discovered that a directory traversal allows
    attackers to read arbitrary files via a certain
    character. (MFSA 2008-44)

  - CVE-2008-4068
    It was discovered that a directory traversal allows
    attackers to bypass security restrictions and obtain
    sensitive information. (MFSA 2008-44)

  - CVE-2008-4070
    It was discovered that a buffer overflow could be
    triggered via a long header in a news article, which
    could lead to arbitrary code execution. (MFSA 2008-46)

  - CVE-2008-4582
    Liu Die Yu and Boris Zbarsky discovered an information
    leak through local shortcut files. (MFSA 2008-47, MFSA
    2008-59)

  - CVE-2008-5012
    Georgi Guninski, Michal Zalewski and Chris Evan
    discovered that the canvas element could be used to
    bypass same-origin restrictions. (MFSA 2008-48)

  - CVE-2008-5014
    Jesse Ruderman discovered that a programming error in
    the window.__proto__.__proto__ object could lead to
    arbitrary code execution. (MFSA 2008-50)

  - CVE-2008-5017
    It was discovered that crashes in the layout engine
    could lead to arbitrary code execution. (MFSA 2008-52)

  - CVE-2008-5018
    It was discovered that crashes in the JavaScript engine
    could lead to arbitrary code execution. (MFSA 2008-52)

  - CVE-2008-5021
    It was discovered that a crash in the nsFrameManager
    might lead to the execution of arbitrary code. (MFSA
    2008-55)

  - CVE-2008-5022
    'moz_bug_r_a4' discovered that the same-origin check in
    nsXMLHttpRequest::NotifyEventListeners() could be
    bypassed. (MFSA 2008-56)

  - CVE-2008-5024
    Chris Evans discovered that quote characters were
    improperly escaped in the default namespace of E4X
    documents. (MFSA 2008-58)

  - CVE-2008-5500
    Jesse Ruderman discovered that the layout engine is
    vulnerable to DoS attacks that might trigger memory
    corruption and an integer overflow. (MFSA 2008-60)

  - CVE-2008-5503
    Boris Zbarsky discovered that an information disclosure
    attack could be performed via XBL bindings. (MFSA
    2008-61)

  - CVE-2008-5506
    Marius Schilder discovered that it is possible to obtain
    sensible data via a XMLHttpRequest. (MFSA 2008-64)

  - CVE-2008-5507
    Chris Evans discovered that it is possible to obtain
    sensible data via a JavaScript URL. (MFSA 2008-65)

  - CVE-2008-5508
    Chip Salzenberg discovered possible phishing attacks via
    URLs with leading whitespaces or control characters.
    (MFSA 2008-66)

  - CVE-2008-5511
    It was discovered that it is possible to perform
    cross-site scripting attacks via an XBL binding to an
    'unloaded document.' (MFSA 2008-68)

  - CVE-2008-5512
    It was discovered that it is possible to run arbitrary
    JavaScript with chrome privileges via unknown vectors.
    (MFSA 2008-68)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1380"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5508"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1696"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the icedove packages.

For the stable distribution (etch) these problems have been fixed in
version 1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1. Packages for
s390 will be provided later.

For the upcoming stable distribution (lenny) these problems will be
fixed soon.

For the unstable (sid) distribution these problems have been fixed in
version 2.0.0.19-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 22, 79, 94, 119, 189, 200, 264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/08");
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
if (deb_check(release:"4.0", prefix:"icedove", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"icedove-dbg", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"icedove-dev", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"icedove-gnome-support", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"icedove-inspector", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"icedove-typeaheadfind", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-thunderbird", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-thunderbird-dev", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-thunderbird-inspector", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-thunderbird-typeaheadfind", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"thunderbird", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"thunderbird-dbg", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"thunderbird-dev", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"thunderbird-gnome-support", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"thunderbird-inspector", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"thunderbird-typeaheadfind", reference:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
