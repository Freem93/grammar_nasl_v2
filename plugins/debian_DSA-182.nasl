#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-182. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15019);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/05/17 23:49:57 $");

  script_cve_id("CVE-2002-0838");
  script_bugtraq_id(5808);
  script_osvdb_id(8651);
  script_xref(name:"DSA", value:"182");

  script_name(english:"Debian DSA-182-1 : kdegraphics - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Zen-parse discovered a buffer overflow in gv, a PostScript and PDF
viewer for X11. The same code is present in kghostview which is part
of the KDE-Graphics package. This problem is triggered by scanning the
PostScript file and can be exploited by an attacker sending a
malformed PostScript or PDF file. The attacker is able to cause
arbitrary code to be run with the privileges of the victim."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-182"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kghostview package.

This problem has been fixed in version 2.2.2-6.8 for the current
stable distribution (woody) and in version 2.2.2-6.9 for the unstable
distribution (sid). The old stable distribution (potato) is not
affected since no KDE is included."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/12/04");
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
if (deb_check(release:"3.0", prefix:"kamera", reference:"2.2.2-6.8")) flag++;
if (deb_check(release:"3.0", prefix:"kcoloredit", reference:"2.2.2-6.8")) flag++;
if (deb_check(release:"3.0", prefix:"kfract", reference:"2.2.2-6.8")) flag++;
if (deb_check(release:"3.0", prefix:"kghostview", reference:"2.2.2-6.8")) flag++;
if (deb_check(release:"3.0", prefix:"kiconedit", reference:"2.2.2-6.8")) flag++;
if (deb_check(release:"3.0", prefix:"kooka", reference:"2.2.2-6.8")) flag++;
if (deb_check(release:"3.0", prefix:"kpaint", reference:"2.2.2-6.8")) flag++;
if (deb_check(release:"3.0", prefix:"kruler", reference:"2.2.2-6.8")) flag++;
if (deb_check(release:"3.0", prefix:"ksnapshot", reference:"2.2.2-6.8")) flag++;
if (deb_check(release:"3.0", prefix:"kview", reference:"2.2.2-6.8")) flag++;
if (deb_check(release:"3.0", prefix:"libkscan-dev", reference:"2.2.2-6.8")) flag++;
if (deb_check(release:"3.0", prefix:"libkscan1", reference:"2.2.2-6.8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
