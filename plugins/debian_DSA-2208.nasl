#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2208. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53224);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/02/16 15:31:55 $");

  script_cve_id("CVE-2011-0414");
  script_bugtraq_id(46491);
  script_xref(name:"DSA", value:"2208");

  script_name(english:"Debian DSA-2208-1 : bind9 - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that BIND, a DNS server, contains a race condition
when processing zones updates in an authoritative server, either
through dynamic DNS updates or incremental zone transfer (IXFR). Such
an update while processing a query could result in deadlock and denial
of service. (CVE-2011-0414 )

In addition, this security update addresses a defect related to the
processing of new DNSSEC DS records by the caching resolver, which may
lead to name resolution failures in the delegated zone. If DNSSEC
validation is enabled, this issue can make domains ending in .COM
unavailable when the DS record for .COM is added to the DNS root zone
on March 31st, 2011. An unpatched server which is affected by this
issue can be restarted, thus re-enabling resolution of .COM domains.
This workaround applies to the version in oldstable, too.

Configurations not using DNSSEC validations are not affected by this
second issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/bind9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2208"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bind9 packages.

For the oldstable distribution (lenny), the DS record issue has been
fixed in version 1:9.6.ESV.R4+dfsg-0+lenny1. (CVE-2011-0414 does not
affect the lenny version.)

For the stable distribution (squeeze), this problem has been fixed in
version 1:9.7.3.dfsg-1~squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"bind9", reference:"1:9.6.ESV.R4+dfsg-0+lenny1")) flag++;
if (deb_check(release:"6.0", prefix:"bind9", reference:"1:9.7.3.dfsg-1~squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"bind9-doc", reference:"1:9.7.3.dfsg-1~squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"bind9-host", reference:"1:9.7.3.dfsg-1~squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"bind9utils", reference:"1:9.7.3.dfsg-1~squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"dnsutils", reference:"1:9.7.3.dfsg-1~squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"host", reference:"1:9.7.3.dfsg-1~squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libbind-dev", reference:"1:9.7.3.dfsg-1~squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libbind9-60", reference:"1:9.7.3.dfsg-1~squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libdns69", reference:"1:9.7.3.dfsg-1~squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libisc62", reference:"1:9.7.3.dfsg-1~squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libisccc60", reference:"1:9.7.3.dfsg-1~squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libisccfg62", reference:"1:9.7.3.dfsg-1~squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"liblwres60", reference:"1:9.7.3.dfsg-1~squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"lwresd", reference:"1:9.7.3.dfsg-1~squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
