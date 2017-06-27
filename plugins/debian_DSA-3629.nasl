#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3629. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92571);
  script_version("$Revision: 2.11 $");
  script_cvs_date("$Date: 2017/03/08 15:07:20 $");

  script_cve_id("CVE-2015-7974", "CVE-2015-7977", "CVE-2015-7978", "CVE-2015-7979", "CVE-2015-8138", "CVE-2015-8158", "CVE-2016-1547", "CVE-2016-1548", "CVE-2016-1550", "CVE-2016-2516", "CVE-2016-2518");
  script_osvdb_id(133378, 133382, 133383, 133384, 133387, 133391, 137711, 137712, 137714, 137732, 137734);
  script_xref(name:"DSA", value:"3629");

  script_name(english:"Debian DSA-3629-1 : ntp - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in the Network Time Protocol
daemon and utility programs :

  - CVE-2015-7974
    Matt Street discovered that insufficient key validation
    allows impersonation attacks between authenticated
    peers.

  - CVE-2015-7977 CVE-2015-7978
    Stephen Gray discovered that a NULL pointer dereference
    and a buffer overflow in the handling of 'ntpdc reslist'
    commands may result in denial of service.

  - CVE-2015-7979
    Aanchal Malhotra discovered that if NTP is configured
    for broadcast mode, an attacker can send malformed
    authentication packets which break associations with the
    server for other broadcast clients.

  - CVE-2015-8138
    Matthew van Gundy and Jonathan Gardner discovered that
    missing validation of origin timestamps in ntpd clients
    may result in denial of service.

  - CVE-2015-8158
    Jonathan Gardner discovered that missing input
    sanitising in ntpq may result in denial of service.

  - CVE-2016-1547
    Stephen Gray and Matthew van Gundy discovered that
    incorrect handling of crypto NAK packets may result in
    denial of service.

  - CVE-2016-1548
    Jonathan Gardner and Miroslav Lichvar discovered that
    ntpd clients could be forced to change from basic
    client/server mode to interleaved symmetric mode,
    preventing time synchronisation.

  - CVE-2016-1550
    Matthew van Gundy, Stephen Gray and Loganaden Velvindron
    discovered that timing leaks in the packet
    authentication code could result in recovery of a
    message digest.

  - CVE-2016-2516
    Yihan Lian discovered that duplicate IPs on 'unconfig'
    directives will trigger an assert.

  - CVE-2016-2518
    Yihan Lian discovered that an OOB memory access could
    potentially crash ntpd."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7977"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/ntp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3629"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ntp packages.

For the stable distribution (jessie), these problems have been fixed
in version 1:4.2.6.p5+dfsg-7+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"ntp", reference:"1:4.2.6.p5+dfsg-7+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ntp-doc", reference:"1:4.2.6.p5+dfsg-7+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ntpdate", reference:"1:4.2.6.p5+dfsg-7+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
