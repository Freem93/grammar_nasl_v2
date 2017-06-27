#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2645. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65558);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/16 15:37:39 $");

  script_cve_id("CVE-2010-2529");
  script_bugtraq_id(41911);
  script_osvdb_id(66681);
  script_xref(name:"DSA", value:"2645");

  script_name(english:"Debian DSA-2645-1 : inetutils - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ovidiu Mara reported in 2010 a vulnerability in the ping util,
commonly used by system and network administrators. By carefully
crafting ICMP responses, an attacker could make the ping command
hangs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/inetutils"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2645"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the inetutils packages.

For the stable distribution (squeeze), this problem has been fixed in
version 2:1.6-3.1+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/15");
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
if (deb_check(release:"6.0", prefix:"inetutils-ftp", reference:"2:1.6-3.1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"inetutils-ftpd", reference:"2:1.6-3.1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"inetutils-inetd", reference:"2:1.6-3.1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"inetutils-ping", reference:"2:1.6-3.1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"inetutils-syslogd", reference:"2:1.6-3.1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"inetutils-talk", reference:"2:1.6-3.1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"inetutils-talkd", reference:"2:1.6-3.1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"inetutils-telnet", reference:"2:1.6-3.1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"inetutils-telnetd", reference:"2:1.6-3.1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"inetutils-tools", reference:"2:1.6-3.1+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
