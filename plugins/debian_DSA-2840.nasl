#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2840. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71902);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/16 15:43:10 $");

  script_cve_id("CVE-2013-2139");
  script_bugtraq_id(60323);
  script_xref(name:"DSA", value:"2840");

  script_name(english:"Debian DSA-2840-1 : srtp - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fernando Russ from Groundworks Technologies reported a buffer overflow
flaw in srtp, Cisco's reference implementation of the Secure Real-time
Transport Protocol (SRTP), in how the
crypto_policy_set_from_profile_for_rtp() function applies
cryptographic profiles to an srtp_policy. A remote attacker could
exploit this vulnerability to crash an application linked against
libsrtp, resulting in a denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=711163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/srtp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/srtp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2840"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the srtp packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 1.4.4~dfsg-6+deb6u1.

For the stable distribution (wheezy), this problem has been fixed in
version 1.4.4+20100615~dfsg-2+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:srtp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libsrtp0", reference:"1.4.4~dfsg-6+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libsrtp0-dev", reference:"1.4.4~dfsg-6+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"srtp-docs", reference:"1.4.4~dfsg-6+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"srtp-utils", reference:"1.4.4~dfsg-6+deb6u1")) flag++;
if (deb_check(release:"7.0", prefix:"libsrtp0", reference:"1.4.4+20100615~dfsg-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libsrtp0-dev", reference:"1.4.4+20100615~dfsg-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"srtp-docs", reference:"1.4.4+20100615~dfsg-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"srtp-utils", reference:"1.4.4+20100615~dfsg-2+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
