#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2569. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62748);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2012-3982", "CVE-2012-3986", "CVE-2012-3990", "CVE-2012-3991", "CVE-2012-4179", "CVE-2012-4180", "CVE-2012-4182", "CVE-2012-4186", "CVE-2012-4188");
  script_bugtraq_id(55922, 55924, 55930, 56121, 56123, 56126, 56129, 56131, 56135);
  script_osvdb_id(86094, 86096, 86098, 86099, 86102, 86104, 86108, 86115, 86117);
  script_xref(name:"DSA", value:"2569");

  script_name(english:"Debian DSA-2569-1 : icedove - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in Icedove, Debian's
version of the Mozilla Thunderbird mail client. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2012-3982
    Multiple unspecified vulnerabilities in the browser
    engine allow remote attackers to cause a denial of
    service (memory corruption and application crash) or
    possibly execute arbitrary code via unknown vectors.

  - CVE-2012-3986
    Icedove does not properly restrict calls to
    DOMWindowUtils methods, which allows remote attackers to
    bypass intended access restrictions via crafted
    JavaScript code.

  - CVE-2012-3990
    A Use-after-free vulnerability in the IME State Manager
    implementation allows remote attackers to execute
    arbitrary code via unspecified vectors, related to the
    nsIContent::GetNameSpaceID function.

  - CVE-2012-3991
    Icedove does not properly restrict JSAPI access to the
    GetProperty function, which allows remote attackers to
    bypass the Same Origin Policy and possibly have
    unspecified other impact via a crafted website.

  - CVE-2012-4179
    A use-after-free vulnerability in the
    nsHTMLCSSUtils::CreateCSSPropertyTxn function allows
    remote attackers to execute arbitrary code or cause a
    denial of service (heap memory corruption) via
    unspecified vectors.

  - CVE-2012-4180
    A heap-based buffer overflow in the
    nsHTMLEditor::IsPrevCharInNodeWhitespace function allows
    remote attackers to execute arbitrary code via
    unspecified vectors.

  - CVE-2012-4182
    A use-after-free vulnerability in the
    nsTextEditRules::WillInsert function allows remote
    attackers to execute arbitrary code or cause a denial of
    service (heap memory corruption) via unspecified
    vectors.

  - CVE-2012-4186
    A heap-based buffer overflow in the
    nsWav-eReader::DecodeAudioData function allows remote
    attackers to execute arbitrary code via unspecified
    vectors.

  - CVE-2012-4188
    A heap-based buffer overflow in the Convolve3x3 function
    allows remote attackers to execute arbitrary code via
    unspecified vectors."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-4179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-4180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-4182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-4186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-4188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/icedove"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2569"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the icedove packages.

For the stable distribution (squeeze), these problems have been fixed
in version 3.0.11-1+squeeze14."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/30");
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
if (deb_check(release:"6.0", prefix:"icedove", reference:"3.0.11-1+squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"icedove-dbg", reference:"3.0.11-1+squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"icedove-dev", reference:"3.0.11-1+squeeze14")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
