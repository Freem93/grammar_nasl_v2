#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2710. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66917);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:43:09 $");

  script_cve_id("CVE-2013-2153", "CVE-2013-2154", "CVE-2013-2155", "CVE-2013-2156");
  script_bugtraq_id(60592, 60594, 60595, 60599);
  script_osvdb_id(94400, 94401, 94402, 94403);
  script_xref(name:"DSA", value:"2710");

  script_name(english:"Debian DSA-2710-1 : xml-security-c - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"James Forshaw from Context Information Security discovered several
vulnerabilities in xml-security-c, an implementation of the XML
Digital Security specification. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2013-2153
    The implementation of XML digital signatures in the
    Santuario-C++ library is vulnerable to a spoofing issue
    allowing an attacker to reuse existing signatures with
    arbitrary content.

  - CVE-2013-2154
    A stack overflow, possibly leading to arbitrary code
    execution, exists in the processing of malformed
    XPointer expressions in the XML Signature Reference
    processing code.

  - CVE-2013-2155
    A bug in the processing of the output length of an
    HMAC-based XML Signature would cause a denial of service
    when processing specially chosen input.

  - CVE-2013-2156
    A heap overflow exists in the processing of the
    PrefixList attribute optionally used in conjunction with
    Exclusive Canonicalization, potentially allowing
    arbitrary code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/xml-security-c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/xml-security-c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2710"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xml-security-c packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 1.5.1-3+squeeze2.

For the stable distribution (wheezy), these problems have been fixed
in version 1.6.1-5+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xml-security-c");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libxml-security-c-dev", reference:"1.5.1-3+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libxml-security-c15", reference:"1.5.1-3+squeeze2")) flag++;
if (deb_check(release:"7.0", prefix:"libxml-security-c-dev", reference:"1.6.1-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libxml-security-c16", reference:"1.6.1-5+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
