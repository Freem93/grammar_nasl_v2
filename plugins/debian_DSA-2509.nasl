#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2509. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59890);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2012-3374");
  script_bugtraq_id(54322);
  script_osvdb_id(83605);
  script_xref(name:"DSA", value:"2509");

  script_name(english:"Debian DSA-2509-1 : pidgin - remote code execution");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ulf Harnhammar found a buffer overflow in Pidgin, a multi protocol
instant messaging client. The vulnerability can be exploited by an
incoming message in the MXit protocol plugin. A remote attacker may
cause a crash, and in some circumstances can lead to remote code
execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/pidgin"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2509"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the pidgin packages.

For the stable distribution (squeeze), this problem has been fixed in
version 2.7.3-1+squeeze3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"finch", reference:"2.7.3-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"finch-dev", reference:"2.7.3-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libpurple-bin", reference:"2.7.3-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libpurple-dev", reference:"2.7.3-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"libpurple0", reference:"2.7.3-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"pidgin", reference:"2.7.3-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"pidgin-data", reference:"2.7.3-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"pidgin-dbg", reference:"2.7.3-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"pidgin-dev", reference:"2.7.3-1+squeeze3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
