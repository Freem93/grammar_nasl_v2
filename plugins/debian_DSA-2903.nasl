#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2903. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73501);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/27 14:13:21 $");

  script_cve_id("CVE-2014-2338");
  script_osvdb_id(105954);
  script_xref(name:"DSA", value:"2903");

  script_name(english:"Debian DSA-2903-1 : strongswan - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An authentication bypass vulnerability was found in charon, the daemon
handling IKEv2 in strongSwan, an IKE/IPsec suite. The state machine
handling the security association (IKE_SA) handled some state
transitions incorrectly.

An attacker can trigger the vulnerability by rekeying an unestablished
IKE_SA during the initiation itself. This will trick the IKE_SA state
to'established' without the need to provide any valid credential.

Vulnerable setups include those actively initiating IKEv2 IKE_SA (like
'clients' or 'roadwarriors') but also during re-authentication
(which can be initiated by the responder). Installations using IKEv1
(pluto daemon in strongSwan 4 and earlier, and IKEv1 code in charon
5.x) is not affected."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/strongswan"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/strongswan"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2903"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the strongswan packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 4.4.1-5.5.

For the stable distribution (wheezy), this problem has been fixed in
version 4.5.2-1.5+deb7u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libstrongswan", reference:"4.4.1-5.5")) flag++;
if (deb_check(release:"6.0", prefix:"strongswan", reference:"4.4.1-5.5")) flag++;
if (deb_check(release:"6.0", prefix:"strongswan-dbg", reference:"4.4.1-5.5")) flag++;
if (deb_check(release:"6.0", prefix:"strongswan-ikev1", reference:"4.4.1-5.5")) flag++;
if (deb_check(release:"6.0", prefix:"strongswan-ikev2", reference:"4.4.1-5.5")) flag++;
if (deb_check(release:"6.0", prefix:"strongswan-nm", reference:"4.4.1-5.5")) flag++;
if (deb_check(release:"6.0", prefix:"strongswan-starter", reference:"4.4.1-5.5")) flag++;
if (deb_check(release:"7.0", prefix:"libstrongswan", reference:"4.5.2-1.5+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"strongswan", reference:"4.5.2-1.5+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"strongswan-dbg", reference:"4.5.2-1.5+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"strongswan-ikev1", reference:"4.5.2-1.5+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"strongswan-ikev2", reference:"4.5.2-1.5+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"strongswan-nm", reference:"4.5.2-1.5+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"strongswan-starter", reference:"4.5.2-1.5+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
