#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-388. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15225);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/05/05 16:01:12 $");

  script_cve_id("CVE-2003-0690", "CVE-2003-0692");
  script_bugtraq_id(8635, 8636);
  script_xref(name:"DSA", value:"388");

  script_name(english:"Debian DSA-388-1 : kdebase - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were discovered in kdebase :

  - CAN-2003-0690 :
    KDM in KDE 3.1.3 and earlier does not verify whether the
    pam_setcred function call succeeds, which may allow
    attackers to gain root privileges by triggering error
    conditions within PAM modules, as demonstrated in
    certain configurations of the MIT pam_krb5 module.

  - CAN-2003-0692 :

    KDM in KDE 3.1.3 and earlier uses a weak session cookie
    generation algorithm that does not provide 128 bits of
    entropy, which allows attackers to guess session cookies
    via brute-force methods and gain access to the user
    session.

These vulnerabilities are described in the following security advisory
from KDE :"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-388"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the current stable distribution (woody) these problems have been
fixed in version 4:2.2.2-14.7.

We recommend that you update your kdebase package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdebase");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
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
if (deb_check(release:"3.0", prefix:"kate", reference:"2.2.2-14.7")) flag++;
if (deb_check(release:"3.0", prefix:"kdebase", reference:"2.2.2-14.7")) flag++;
if (deb_check(release:"3.0", prefix:"kdebase-audiolibs", reference:"2.2.2-14.7")) flag++;
if (deb_check(release:"3.0", prefix:"kdebase-dev", reference:"2.2.2-14.7")) flag++;
if (deb_check(release:"3.0", prefix:"kdebase-doc", reference:"2.2.2-14.7")) flag++;
if (deb_check(release:"3.0", prefix:"kdebase-libs", reference:"2.2.2-14.7")) flag++;
if (deb_check(release:"3.0", prefix:"kdewallpapers", reference:"2.2.2-14.7")) flag++;
if (deb_check(release:"3.0", prefix:"kdm", reference:"2.2.2-14.7")) flag++;
if (deb_check(release:"3.0", prefix:"konqueror", reference:"2.2.2-14.7")) flag++;
if (deb_check(release:"3.0", prefix:"konsole", reference:"2.2.2-14.7")) flag++;
if (deb_check(release:"3.0", prefix:"kscreensaver", reference:"2.2.2-14.7")) flag++;
if (deb_check(release:"3.0", prefix:"libkonq-dev", reference:"2.2.2-14.7")) flag++;
if (deb_check(release:"3.0", prefix:"libkonq3", reference:"2.2.2-14.7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
