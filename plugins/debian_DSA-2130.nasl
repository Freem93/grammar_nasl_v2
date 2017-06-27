#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2130. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51127);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/05/03 11:20:11 $");

  script_cve_id("CVE-2010-3613", "CVE-2010-3614", "CVE-2010-3762");
  script_bugtraq_id(45133, 45137);
  script_xref(name:"DSA", value:"2130");

  script_name(english:"Debian DSA-2130-1 : bind9 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in BIND, an
implementation of the DNS protocol suite. The Common Vulnerabilities
and Exposures project identifies the following problems :

  - CVE-2010-3762
    When DNSSEC validation is enabled, BIND does not
    properly handle certain bad signatures if multiple trust
    anchors exist for a single zone, which allows remote
    attackers to cause a denial of service (server crash)
    via a DNS query.

  - CVE-2010-3614
    BIND does not properly determine the security status of
    an NS RRset during a DNSKEY algorithm rollover, which
    may lead to zone unavailability during rollovers.

  - CVE-2010-3613
    BIND does not properly handle the combination of signed
    negative responses and corresponding RRSIG records in
    the cache, which allows remote attackers to cause a
    denial of service (server crash) via a query for cached
    data.

In addition, this security update improves compatibility with
previously installed versions of the bind9 package. As a result, it is
necessary to initiate the update with 'apt-get dist-upgrade' instead
of 'apt-get update'."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3613"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2130"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bind9 packages.

For the stable distribution (lenny), these problems have been fixed in
version 1:9.6.ESV.R3+dfsg-0+lenny1.

For the upcoming stable distribution (squeeze) and the unstable
distribution (sid), these problems have been fixed in version
1:9.7.2.dfsg.P3-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/12");
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
if (deb_check(release:"5.0", prefix:"bind9", reference:"1:9.6.ESV.R3+dfsg-0+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"bind9-doc", reference:"1:9.6.ESV.R3+dfsg-0+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"bind9-host", reference:"1:9.6.ESV.R3+dfsg-0+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"bind9utils", reference:"1:9.6.ESV.R3+dfsg-0+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"dnsutils", reference:"1:9.6.ESV.R3+dfsg-0+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libbind-dev", reference:"1:9.6.ESV.R3+dfsg-0+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libbind9-50", reference:"1:9.6.ESV.R3+dfsg-0+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libdns58", reference:"1:9.6.ESV.R3+dfsg-0+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libisc50", reference:"1:9.6.ESV.R3+dfsg-0+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libisccc50", reference:"1:9.6.ESV.R3+dfsg-0+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libisccfg50", reference:"1:9.6.ESV.R3+dfsg-0+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"liblwres50", reference:"1:9.6.ESV.R3+dfsg-0+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"lwresd", reference:"1:9.6.ESV.R3+dfsg-0+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
