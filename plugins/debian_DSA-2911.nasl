#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2911. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73657);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/19 17:45:44 $");

  script_cve_id("CVE-2014-1493", "CVE-2014-1497", "CVE-2014-1505", "CVE-2014-1508", "CVE-2014-1510", "CVE-2014-1511", "CVE-2014-1512", "CVE-2014-1513", "CVE-2014-1514");
  script_bugtraq_id(66203, 66206, 66207, 66209, 66240, 66412, 66418, 66423, 66426);
  script_xref(name:"DSA", value:"2911");

  script_name(english:"Debian DSA-2911-1 : icedove - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues have been found in Icedove, Debian's version
of the Mozilla Thunderbird mail and news client. Multiple memory
safety errors, out of bound reads, use-after-frees and other
implementation errors may lead to the execution of arbitrary code,
information disclosure or denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/icedove"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2911"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the icedove packages.

For the stable distribution (wheezy), these problems have been fixed
in version 24.4.0-1~deb7u1. This updates Icedove to the Extended
Support Release (ESR) branch 24. An updated and compatible version of
Enigmail is included with this update."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox WebIDL Privileged Javascript Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/23");
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
if (deb_check(release:"7.0", prefix:"calendar-google-provider", reference:"24.4.0-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedove", reference:"24.4.0-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedove-dbg", reference:"24.4.0-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedove-dev", reference:"24.4.0-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"iceowl-extension", reference:"24.4.0-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
