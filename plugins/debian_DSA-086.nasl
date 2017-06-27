#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-086. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14923);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/06/20 17:20:09 $");

  script_cve_id("CVE-2001-0144", "CVE-2001-0361");
  script_osvdb_id(795);
  script_xref(name:"DSA", value:"086");

  script_name(english:"Debian DSA-086-1 : ssh-nonfree - remote root exploit");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"We have received reports that the 'SSH CRC-32 compensation attack
detector vulnerability' is being actively exploited. This is the same
integer type error previously corrected for OpenSSH in DSA-027-1.
OpenSSH (the Debian ssh package) was fixed at that time, but
ssh-nonfree and ssh-socks were not.

Though packages in the non-free section of the archive are not
officially supported by the Debian project, we are taking the unusual
step of releasing updated ssh-nonfree/ssh-socks packages for those
users who have not yet migrated to OpenSSH. However, we do recommend
that our users migrate to the regularly supported, DFSG-free 'ssh'
package as soon as possible. ssh 1.2.3-9.3 is the OpenSSH package
available in Debian 2.2r4.

The fixed ssh-nonfree/ssh-socks packages are available in version
1.2.27-6.2 for use with Debian 2.2 (potato) and version 1.2.27-8 for
use with the Debian unstable/testing distribution. Note that the new
ssh-nonfree/ssh-socks packages remove the setuid bit from the ssh
binary, disabling rhosts-rsa authentication. If you need this
functionality, run

chmod u+s /usr/bin/ssh1

after installing the new package."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2001/dsa-086"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected ssh-nonfree, and ssh-socks packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ssh-nonfree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ssh-socks");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2001/02/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"ssh-askpass-nonfree", reference:"1.2.27-6.2")) flag++;
if (deb_check(release:"2.2", prefix:"ssh-nonfree", reference:"1.2.27-6.2")) flag++;
if (deb_check(release:"2.2", prefix:"ssh-socks", reference:"1.2.27-6.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
