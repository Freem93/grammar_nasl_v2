#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1948. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44813);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/07/10 14:11:55 $");

  script_cve_id("CVE-2009-3563");
  script_osvdb_id(60847);
  script_xref(name:"DSA", value:"1948");

  script_name(english:"Debian DSA-1948-1 : ntp - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Robin Park and Dmitri Vinokurov discovered that the daemon component
of the ntp package, a reference implementation of the NTP protocol, is
not properly reacting to certain incoming packets.

An unexpected NTP mode 7 packet (MODE_PRIVATE) with spoofed IP data
can lead ntpd to reply with a mode 7 response to the spoofed address.
This may result in the service playing packet ping-pong with other ntp
servers or even itself which causes CPU usage and excessive disk use
due to logging. An attacker can use this to conduct denial of service
attacks."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=560074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1948"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ntp packages.

For the oldstable distribution (etch), this problem has been fixed in
version 1:4.2.2.p4+dfsg-2etch4.

For the stable distribution (lenny), this problem has been fixed in
version 1:4.2.4p4+dfsg-8lenny3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"ntp", reference:"1:4.2.2.p4+dfsg-2etch4")) flag++;
if (deb_check(release:"4.0", prefix:"ntp-doc", reference:"1:4.2.2.p4+dfsg-2etch4")) flag++;
if (deb_check(release:"4.0", prefix:"ntp-refclock", reference:"1:4.2.2.p4+dfsg-2etch4")) flag++;
if (deb_check(release:"4.0", prefix:"ntp-simple", reference:"1:4.2.2.p4+dfsg-2etch4")) flag++;
if (deb_check(release:"4.0", prefix:"ntpdate", reference:"1:4.2.2.p4+dfsg-2etch4")) flag++;
if (deb_check(release:"5.0", prefix:"ntp", reference:"1:4.2.4p4+dfsg-8lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"ntp-doc", reference:"1:4.2.4p4+dfsg-8lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"ntpdate", reference:"1:4.2.4p4+dfsg-8lenny3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
