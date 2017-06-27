#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2665. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66281);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:37:40 $");

  script_cve_id("CVE-2013-2944");
  script_bugtraq_id(59580);
  script_osvdb_id(92878);
  script_xref(name:"DSA", value:"2665");

  script_name(english:"Debian DSA-2665-1 : strongswan - authentication bypass");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Kevin Wojtysiak discovered a vulnerability in strongSwan, an IPsec
based VPN solution.

When using the OpenSSL plugin for ECDSA based authentication, an
empty, zeroed or otherwise invalid signature is handled as a
legitimate one. An attacker could use a forged signature to
authenticate like a legitimate user and gain access to the VPN (and
everything protected by this).

While the issue looks like CVE-2012-2388 (RSA signature based
authentication bypass), it is unrelated."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-2388"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/strongswan"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2665"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the strongswan packages.

For the stable distribution (squeeze), this problem has been fixed in
version 4.4.1-5.3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/01");
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
if (deb_check(release:"6.0", prefix:"libstrongswan", reference:"4.4.1-5.3")) flag++;
if (deb_check(release:"6.0", prefix:"strongswan", reference:"4.4.1-5.3")) flag++;
if (deb_check(release:"6.0", prefix:"strongswan-dbg", reference:"4.4.1-5.3")) flag++;
if (deb_check(release:"6.0", prefix:"strongswan-ikev1", reference:"4.4.1-5.3")) flag++;
if (deb_check(release:"6.0", prefix:"strongswan-ikev2", reference:"4.4.1-5.3")) flag++;
if (deb_check(release:"6.0", prefix:"strongswan-nm", reference:"4.4.1-5.3")) flag++;
if (deb_check(release:"6.0", prefix:"strongswan-starter", reference:"4.4.1-5.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
