#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3223. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82745);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/07/14 13:43:55 $");

  script_cve_id("CVE-2015-1798", "CVE-2015-1799", "CVE-2015-3405");
  script_osvdb_id(120350, 120351);
  script_xref(name:"DSA", value:"3223");

  script_name(english:"Debian DSA-3223-1 : ntp - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in ntp, an implementation of
the Network Time Protocol :

  - CVE-2015-1798
    When configured to use a symmetric key with an NTP peer,
    ntpd would accept packets without MAC as if they had a
    valid MAC. This could allow a remote attacker to bypass
    the packet authentication and send malicious packets
    without having to know the symmetric key.

  - CVE-2015-1799
    When peering with other NTP hosts using authenticated
    symmetric association, ntpd would update its internal
    state variables before the MAC of the NTP messages was
    validated. This could allow a remote attacker to cause a
    denial of service by impeding synchronization between
    NTP peers.

Additionally, it was discovered that generating MD5 keys using
ntp-keygen on big endian machines would either trigger an endless
loop, or generate non-random keys."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=782095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/ntp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/ntp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3223"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ntp packages.

For the stable distribution (wheezy), these problems have been fixed
in version 1:4.2.6.p5+dfsg-2+deb7u4.

For the stable distribution (jessie), these problems have been fixed
in version 1:4.2.6.p5+dfsg-7."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"ntp", reference:"1:4.2.6.p5+dfsg-2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"ntp-doc", reference:"1:4.2.6.p5+dfsg-2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"ntpdate", reference:"1:4.2.6.p5+dfsg-2+deb7u4")) flag++;
if (deb_check(release:"8.0", prefix:"ntp", reference:"1:4.2.6.p5+dfsg-7")) flag++;
if (deb_check(release:"8.0", prefix:"ntp-doc", reference:"1:4.2.6.p5+dfsg-7")) flag++;
if (deb_check(release:"8.0", prefix:"ntpdate", reference:"1:4.2.6.p5+dfsg-7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
