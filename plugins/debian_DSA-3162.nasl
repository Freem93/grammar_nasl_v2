#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3162. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81409);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/07/19 04:39:47 $");

  script_cve_id("CVE-2015-1349");
  script_osvdb_id(118546);
  script_xref(name:"DSA", value:"3162");

  script_name(english:"Debian DSA-3162-1 : bind9 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jan-Piet Mens discovered that the BIND DNS server would crash when
processing an invalid DNSSEC key rollover, either due to an error on
the zone operator's part, or due to interference with network traffic
by an attacker. This issue affects configurations with the directives
'dnssec-validation auto;' (as enabled in the Debian default
configuration) or 'dnssec-lookaside auto;'."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/bind9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3162"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bind9 packages.

For the stable distribution (wheezy), this problem has been fixed in
version 1:9.8.4.dfsg.P1-6+nmu2+deb7u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/19");
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
if (deb_check(release:"7.0", prefix:"bind9", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"bind9-doc", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"bind9-host", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"bind9utils", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"dnsutils", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"host", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libbind-dev", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libbind9-80", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libdns88", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libisc84", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libisccc80", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libisccfg82", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"liblwres80", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"lwresd", reference:"1:9.8.4.dfsg.P1-6+nmu2+deb7u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
