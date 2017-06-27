#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1118. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(22660);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2006-1942", "CVE-2006-2775", "CVE-2006-2776", "CVE-2006-2777", "CVE-2006-2778", "CVE-2006-2779", "CVE-2006-2780", "CVE-2006-2781", "CVE-2006-2782", "CVE-2006-2783", "CVE-2006-2784", "CVE-2006-2785", "CVE-2006-2786", "CVE-2006-2787");
  script_bugtraq_id(18228);
  script_osvdb_id(24713, 26298, 26299, 26300, 26301, 26302, 26303, 26304, 26305, 26306, 26307, 26308, 26309, 26310, 26311, 26313, 26314, 26315, 55359, 55360);
  script_xref(name:"CERT", value:"237257");
  script_xref(name:"CERT", value:"243153");
  script_xref(name:"CERT", value:"421529");
  script_xref(name:"CERT", value:"466673");
  script_xref(name:"CERT", value:"575969");
  script_xref(name:"DSA", value:"1118");

  script_name(english:"Debian DSA-1118-1 : mozilla - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security related problems have been discovered in Mozilla. The
Common Vulnerabilities and Exposures project identifies the following
vulnerabilities :

  - CVE-2006-1942
    Eric Foley discovered that a user can be tricked to
    expose a local file to a remote attacker by displaying a
    local file as image in connection with other
    vulnerabilities. [MFSA-2006-39]

  - CVE-2006-2775
    XUL attributes are associated with the wrong URL under
    certain circumstances, which might allow remote
    attackers to bypass restrictions. [MFSA-2006-35]

  - CVE-2006-2776
    Paul Nickerson discovered that content-defined setters
    on an object prototype were getting called by privileged
    user interface code, and 'moz_bug_r_a4' demonstrated
    that the higher privilege level could be passed along to
    the content-defined attack code. [MFSA-2006-37]

  - CVE-2006-2777
    A vulnerability allows remote attackers to execute
    arbitrary code and create notifications that are
    executed in a privileged context. [MFSA-2006-43]

  - CVE-2006-2778
    Mikolaj Habryn discovered a buffer overflow in the
    crypto.signText function that allows remote attackers to
    execute arbitrary code via certain optional Certificate
    Authority name arguments. [MFSA-2006-38]

  - CVE-2006-2779
    Mozilla team members discovered several crashes during
    testing of the browser engine showing evidence of memory
    corruption which may also lead to the execution of
    arbitrary code. This problem has only partially been
    corrected. [MFSA-2006-32]

  - CVE-2006-2780
    An integer overflow allows remote attackers to cause a
    denial of service and may permit the execution of
    arbitrary code. [MFSA-2006-32]

  - CVE-2006-2781
    Masatoshi Kimura discovered a double-free vulnerability
    that allows remote attackers to cause a denial of
    service and possibly execute arbitrary code via a VCard.
    [MFSA-2006-40]

  - CVE-2006-2782
    Chuck McAuley discovered that a text input box can be
    pre-filled with a filename and then turned into a
    file-upload control, allowing a malicious website to
    steal any local file whose name they can guess.
    [MFSA-2006-41, MFSA-2006-23, CVE-2006-1729]

  - CVE-2006-2783
    Masatoshi Kimura discovered that the Unicode
    Byte-order-Mark (BOM) is stripped from UTF-8 pages
    during the conversion to Unicode before the parser sees
    the web page, which allows remote attackers to conduct
    cross-site scripting (XSS) attacks. [MFSA-2006-42]

  - CVE-2006-2784
    Paul Nickerson discovered that the fix for CVE-2005-0752
    can be bypassed using nested javascript: URLs, allowing
    the attacker to execute privileged code. [MFSA-2005-34,
    MFSA-2006-36]

  - CVE-2006-2785
    Paul Nickerson demonstrated that if an attacker could
    convince a user to right-click on a broken image and
    choose 'View Image' from the context menu then he could
    get JavaScript to run. [MFSA-2006-34]

  - CVE-2006-2786
    Kazuho Oku discovered that Mozilla's lenient handling of
    HTTP header syntax may allow remote attackers to trick
    the browser to interpret certain responses as if they
    were responses from two different sites. [MFSA-2006-33]

  - CVE-2006-2787
    The Mozilla researcher 'moz_bug_r_a4' discovered that
    JavaScript run via EvalInSandbox can escape the sandbox
    and gain elevated privilege. [MFSA-2006-31]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1942"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2781"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-0752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1118"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Mozilla packages.

For the stable distribution (sarge) these problems have been fixed in
version 1.7.8-1sarge7.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 94, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mozilla");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/05");
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
if (deb_check(release:"3.1", prefix:"libnspr-dev", reference:"1.7.8-1sarge7.1")) flag++;
if (deb_check(release:"3.1", prefix:"libnspr4", reference:"1.7.8-1sarge7.1")) flag++;
if (deb_check(release:"3.1", prefix:"libnss-dev", reference:"1.7.8-1sarge7.1")) flag++;
if (deb_check(release:"3.1", prefix:"libnss3", reference:"1.7.8-1sarge7.1")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla", reference:"1.7.8-1sarge7.1")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-browser", reference:"1.7.8-1sarge7.1")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-calendar", reference:"1.7.8-1sarge7.1")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-chatzilla", reference:"1.7.8-1sarge7.1")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-dev", reference:"1.7.8-1sarge7.1")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-dom-inspector", reference:"1.7.8-1sarge7.1")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-js-debugger", reference:"1.7.8-1sarge7.1")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-mailnews", reference:"1.7.8-1sarge7.1")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-psm", reference:"1.7.8-1sarge7.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
