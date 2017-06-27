#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-868. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(20071);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2014/05/22 11:11:54 $");

  script_cve_id("CVE-2005-2701", "CVE-2005-2702", "CVE-2005-2703", "CVE-2005-2704", "CVE-2005-2705", "CVE-2005-2706", "CVE-2005-2707", "CVE-2005-2871", "CVE-2005-2968");
  script_bugtraq_id(14784);
  script_osvdb_id(19255, 19589, 19643, 19644, 19645, 19646, 19647, 19648, 19649);
  script_xref(name:"CERT", value:"573857");
  script_xref(name:"DSA", value:"868");

  script_name(english:"Debian DSA-868-1 : mozilla-thunderbird - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security-related problems have been discovered in Mozilla and
derived programs. Some of the following problems don't exactly apply
to Mozilla Thunderbird, even though the code is present. In order to
keep the codebase in sync with upstream it has been altered
nevertheless. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CAN-2005-2871
    Tom Ferris discovered a bug in the IDN hostname handling
    of Mozilla that allows remote attackers to cause a
    denial of service and possibly execute arbitrary code
    via a hostname with dashes.

  - CAN-2005-2701

    A buffer overflow allows remote attackers to execute
    arbitrary code via an XBM image file that ends in a
    large number of spaces instead of the expected end tag.

  - CAN-2005-2702

    Mats Palmgren discovered a buffer overflow in the
    Unicode string parser that allows a specially crafted
    Unicode sequence to overflow a buffer and cause
    arbitrary code to be executed.

  - CAN-2005-2703

    Remote attackers could spoof HTTP headers of XML HTTP
    requests via XMLHttpRequest and possibly use the client
    to exploit vulnerabilities in servers or proxies.

  - CAN-2005-2704

    Remote attackers could spoof DOM objects via an XBL
    control that implements an internal XPCOM interface.

  - CAN-2005-2705

    Georgi Guninski discovered an integer overflow in the
    JavaScript engine that might allow remote attackers to
    execute arbitrary code.

  - CAN-2005-2706

    Remote attackers could execute JavaScript code with
    chrome privileges via an about: page such as
    about:mozilla.

  - CAN-2005-2707

    Remote attackers could spawn windows without user
    interface components such as the address and status bar
    that could be used to conduct spoofing or phishing
    attacks.

  - CAN-2005-2968

    Peter Zelezny discovered that shell metacharacters are
    not properly escaped when they are passed to a shell
    script and allow the execution of arbitrary commands,
    e.g. when a malicious URL is automatically copied from
    another program into Mozilla as default browser."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=327366"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=329778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-868"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mozilla-thunderbird package.

For the stable distribution (sarge) these problems have been fixed in
version 1.0.2-2.sarge1.0.7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/24");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"mozilla-thunderbird", reference:"1.0.2-2.sarge1.0.7")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-thunderbird-dev", reference:"1.0.2-2.sarge1.0.7")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-thunderbird-inspector", reference:"1.0.2-2.sarge1.0.7")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-thunderbird-offline", reference:"1.0.2-2.sarge1.0.7")) flag++;
if (deb_check(release:"3.1", prefix:"mozilla-thunderbird-typeaheadfind", reference:"1.0.2-2.sarge1.0.7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
