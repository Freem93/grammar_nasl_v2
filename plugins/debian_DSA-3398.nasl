#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3398. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86888);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/04/28 18:33:24 $");

  script_cve_id("CVE-2015-8023");
  script_osvdb_id(130318);
  script_xref(name:"DSA", value:"3398");

  script_name(english:"Debian DSA-3398-1 : strongswan - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tobias Brunner found an authentication bypass vulnerability in
strongSwan, an IKE/IPsec suite.

Due to insufficient validation of its local state the server
implementation of the EAP-MSCHAPv2 protocol in the eap-mschapv2 plugin
can be tricked into successfully concluding the authentication without
providing valid credentials.

It's possible to recognize such attacks by looking at the server logs.
The following log message would be seen during the client
authentication :

EAP method EAP_MSCHAPV2 succeeded, no MSK established"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/strongswan"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/strongswan"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3398"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the strongswan packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 4.5.2-1.5+deb7u8.

For the stable distribution (jessie), this problem has been fixed in
version 5.2.1-6+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libstrongswan", reference:"4.5.2-1.5+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"strongswan", reference:"4.5.2-1.5+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"strongswan-dbg", reference:"4.5.2-1.5+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"strongswan-ikev1", reference:"4.5.2-1.5+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"strongswan-ikev2", reference:"4.5.2-1.5+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"strongswan-nm", reference:"4.5.2-1.5+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"strongswan-starter", reference:"4.5.2-1.5+deb7u8")) flag++;
if (deb_check(release:"8.0", prefix:"charon-cmd", reference:"5.2.1-6+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libcharon-extra-plugins", reference:"5.2.1-6+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libstrongswan", reference:"5.2.1-6+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libstrongswan-extra-plugins", reference:"5.2.1-6+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libstrongswan-standard-plugins", reference:"5.2.1-6+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan", reference:"5.2.1-6+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-charon", reference:"5.2.1-6+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-dbg", reference:"5.2.1-6+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-ike", reference:"5.2.1-6+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-ikev1", reference:"5.2.1-6+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-ikev2", reference:"5.2.1-6+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-libcharon", reference:"5.2.1-6+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-nm", reference:"5.2.1-6+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"strongswan-starter", reference:"5.2.1-6+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
