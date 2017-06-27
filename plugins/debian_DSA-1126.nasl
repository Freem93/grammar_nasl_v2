#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1126. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22668);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/05 14:49:55 $");

  script_cve_id("CVE-2006-2898");
  script_bugtraq_id(18295);
  script_osvdb_id(26187);
  script_xref(name:"DSA", value:"1126");

  script_name(english:"Debian DSA-1126-1 : asterisk - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A problem has been discovered in the IAX2 channel driver of Asterisk,
an Open Source Private Branch Exchange and telephony toolkit, which
may allow a remote attacker to cause a crash of the Asterisk server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1126"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the asterisk packages.

The old stable distribution (woody) is not affected by this problem.

For the stable distribution (sarge) this problem has been fixed in
version 1.0.7.dfsg.1-2sarge3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"asterisk", reference:"1.0.7.dfsg.1-2sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"asterisk-config", reference:"1.0.7.dfsg.1-2sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"asterisk-dev", reference:"1.0.7.dfsg.1-2sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"asterisk-doc", reference:"1.0.7.dfsg.1-2sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"asterisk-gtk-console", reference:"1.0.7.dfsg.1-2sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"asterisk-h323", reference:"1.0.7.dfsg.1-2sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"asterisk-sounds-main", reference:"1.0.7.dfsg.1-2sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"asterisk-web-vmail", reference:"1.0.7.dfsg.1-2sarge3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
