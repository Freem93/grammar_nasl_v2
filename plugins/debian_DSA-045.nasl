#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-045. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14882);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2013/11/21 11:45:12 $");

  script_cve_id("CVE-2001-0414");
  script_bugtraq_id(2450);
  script_osvdb_id(805);
  script_xref(name:"DSA", value:"045");

  script_name(english:"Debian DSA-045-2 : ntpd - remote root exploit");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Przemyslaw Frasunek <venglin@FREEBSD.LUBLIN.PL> reported that ntp
daemons such as that released with Debian GNU/Linux are vulnerable to
a buffer overflow that can lead to a remote root exploit. A previous
advisory (DSA-045-1) partially addressed this issue, but introduced a
potential denial of service attack. This has been corrected for Debian
2.2 (potato) in ntp version 4.0.99g-2potato2."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2001/dsa-045"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected ntpd package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'NTP Daemon readvar Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2001/04/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"ntp", reference:"4.0.99g-2potato2")) flag++;
if (deb_check(release:"2.2", prefix:"ntp-doc", reference:"4.0.99g-2potato2")) flag++;
if (deb_check(release:"2.2", prefix:"ntpdate", reference:"4.0.99g-2potato2")) flag++;
if (deb_check(release:"2.2", prefix:"xntp3", reference:"4.0.99g-2potato2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
