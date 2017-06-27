#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2054. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46829);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/05/03 11:20:11 $");

  script_cve_id("CVE-2010-0097", "CVE-2010-0290", "CVE-2010-0382");
  script_bugtraq_id(37118, 37865);
  script_xref(name:"DSA", value:"2054");

  script_name(english:"Debian DSA-2054-1 : bind9 - DNS cache poisoning");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several cache-poisoning vulnerabilities have been discovered in BIND.
These vulnerabilities apply only if DNSSEC validation is enabled and
trust anchors have been installed, which is not the default.

The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2010-0097
    BIND does not properly validate DNSSEC NSEC records,
    which allows remote attackers to add the Authenticated
    Data (AD) flag to a forged NXDOMAIN response for an
    existing domain.

  - CVE-2010-0290
    When processing crafted responses containing CNAME or
    DNAME records, BIND is subject to a DNS cache poisoning
    vulnerability, provided that DNSSEC validation is
    enabled and trust anchors have been installed.

  - CVE-2010-0382
    When processing certain responses containing
    out-of-bailiwick data, BIND is subject to a DNS cache
    poisoning vulnerability, provided that DNSSEC validation
    is enabled and trust anchors have been installed.

In addition, this update introduce a more conservative query behavior
in the presence of repeated DNSSEC validation failures, addressing the
'roll over and die' phenomenon. The new version also supports the
cryptographic algorithm used by the upcoming signed ICANN DNS root
(RSASHA256 from RFC 5702), and the NSEC3 secure denial of existence
algorithm used by some signed top-level domains.

This update is based on a new upstream version of BIND 9, 9.6-ESV-R1.
Because of the scope of changes, extra care is recommended when
installing the update. Due to ABI changes, new Debian packages are
included, and the update has to be installed using 'apt-get
dist-upgrade' (or an equivalent aptitude command)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0290"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2054"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bind9 packages.

For the stable distribution (lenny), these problems have been fixed in
version 1:9.6.ESV.R1+dfsg-0+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/08");
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
if (deb_check(release:"5.0", prefix:"bind9", reference:"1:9.6.ESV.R1+dfsg-0+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"bind9-doc", reference:"1:9.6.ESV.R1+dfsg-0+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"bind9-host", reference:"1:9.6.ESV.R1+dfsg-0+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"bind9utils", reference:"1:9.6.ESV.R1+dfsg-0+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"dnsutils", reference:"1:9.6.ESV.R1+dfsg-0+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libbind-dev", reference:"1:9.6.ESV.R1+dfsg-0+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libbind9-50", reference:"1:9.6.ESV.R1+dfsg-0+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libdns55", reference:"1:9.6.ESV.R1+dfsg-0+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libisc52", reference:"1:9.6.ESV.R1+dfsg-0+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libisccc50", reference:"1:9.6.ESV.R1+dfsg-0+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libisccfg50", reference:"1:9.6.ESV.R1+dfsg-0+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"liblwres50", reference:"1:9.6.ESV.R1+dfsg-0+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"lwresd", reference:"1:9.6.ESV.R1+dfsg-0+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
