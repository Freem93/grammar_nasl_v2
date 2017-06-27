#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2617. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64397);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2013-0213", "CVE-2013-0214");
  script_bugtraq_id(57631);
  script_osvdb_id(89626, 89627);
  script_xref(name:"DSA", value:"2617");

  script_name(english:"Debian DSA-2617-1 : samba - several issues");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jann Horn had reported two vulnerabilities in Samba, a popular
cross-platform network file and printer sharing suite. In particular,
these vulnerabilities affect to SWAT, the Samba Web Administration
Tool.

  - CVE-2013-0213: Clickjacking issue in SWAT
    An attacker can integrate a SWAT page into a malicious
    web page via a frame or iframe and then overlaid by
    other content. If an authenticated valid user interacts
    with this malicious web page, she might perform
    unintended changes in the Samba settings.

  - CVE-2013-0214: Potential Cross-site request forgery
    An attacker can persuade a valid SWAT user, who is
    logged in as root, to click in a malicious link and
    trigger arbitrary unintended changes in the Samba
    settings. In order to be vulnerable, the attacker needs
    to know the victim's password."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-0213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-0214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/samba"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2617"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the samba packages.

For the stable distribution (squeeze), these problems have been fixed
in version 2:3.5.6~dfsg-3squeeze9."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libpam-smbpass", reference:"2:3.5.6~dfsg-3squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"libsmbclient", reference:"2:3.5.6~dfsg-3squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"libsmbclient-dev", reference:"2:3.5.6~dfsg-3squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"libwbclient0", reference:"2:3.5.6~dfsg-3squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"samba", reference:"2:3.5.6~dfsg-3squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"samba-common", reference:"2:3.5.6~dfsg-3squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"samba-common-bin", reference:"2:3.5.6~dfsg-3squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"samba-dbg", reference:"2:3.5.6~dfsg-3squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"samba-doc", reference:"2:3.5.6~dfsg-3squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"samba-doc-pdf", reference:"2:3.5.6~dfsg-3squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"samba-tools", reference:"2:3.5.6~dfsg-3squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"smbclient", reference:"2:3.5.6~dfsg-3squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"swat", reference:"2:3.5.6~dfsg-3squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"winbind", reference:"2:3.5.6~dfsg-3squeeze9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
