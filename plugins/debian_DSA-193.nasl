#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-193. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15030);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/17 23:54:23 $");

  script_cve_id("CVE-2002-1247");
  script_bugtraq_id(6157);
  script_xref(name:"DSA", value:"193");

  script_name(english:"Debian DSA-193-1 : kdenetwork - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"iDEFENSE reports a security vulnerability in the klisa package, that
provides a LAN information service similar to 'Network Neighbourhood',
which was discovered by Texonet. It is possible for a local attacker
to exploit a buffer overflow condition in resLISa, a restricted
version of KLISa. The vulnerability exists in the parsing of the
LOGNAME environment variable, an overly long value will overwrite the
instruction pointer thereby allowing an attacker to seize control of
the executable."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.idefense.com/advisory/11.11.02.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-193"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the klisa package immediately.

This problem has been fixed in version 2.2.2-14.2 for the current
stable distribution (woody) and in version 2.2.2-14.3 for the unstable
distribution (sid). The old stable distribution (potato) is not
affected since it doesn't contain a kdenetwork package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdenetwork");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
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
if (deb_check(release:"3.0", prefix:"kdict", reference:"2.2.2-14.2")) flag++;
if (deb_check(release:"3.0", prefix:"kit", reference:"2.2.2-14.2")) flag++;
if (deb_check(release:"3.0", prefix:"klisa", reference:"2.2.2-14.2")) flag++;
if (deb_check(release:"3.0", prefix:"kmail", reference:"2.2.2-14.2")) flag++;
if (deb_check(release:"3.0", prefix:"knewsticker", reference:"2.2.2-14.2")) flag++;
if (deb_check(release:"3.0", prefix:"knode", reference:"2.2.2-14.2")) flag++;
if (deb_check(release:"3.0", prefix:"korn", reference:"2.2.2-14.2")) flag++;
if (deb_check(release:"3.0", prefix:"kppp", reference:"2.2.2-14.2")) flag++;
if (deb_check(release:"3.0", prefix:"ksirc", reference:"2.2.2-14.2")) flag++;
if (deb_check(release:"3.0", prefix:"ktalkd", reference:"2.2.2-14.2")) flag++;
if (deb_check(release:"3.0", prefix:"libkdenetwork1", reference:"2.2.2-14.2")) flag++;
if (deb_check(release:"3.0", prefix:"libmimelib-dev", reference:"2.2.2-14.2")) flag++;
if (deb_check(release:"3.0", prefix:"libmimelib1", reference:"2.2.2-14.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
