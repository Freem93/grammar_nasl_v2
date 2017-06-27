#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2290. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55770);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2011-2522", "CVE-2011-2694");
  script_bugtraq_id(48899, 48901);
  script_osvdb_id(74071, 74072);
  script_xref(name:"DSA", value:"2290");

  script_name(english:"Debian DSA-2290-1 : samba - XSS");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Samba Web Administration Tool (SWAT) contains several cross-site
request forgery (CSRF) vulnerabilities (CVE-2011-2522 ) and a
cross-site scripting vulnerability (CVE-2011-2694 )."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/samba"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2290"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the samba packages.

For the oldstable distribution (lenny), these problems have been fixed
in version 2:3.2.5-4lenny15.

For the stable distribution (squeeze), these problems have been fixed
in version 2:3.5.6~dfsg-3squeeze5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"samba", reference:"2:3.2.5-4lenny15")) flag++;
if (deb_check(release:"6.0", prefix:"libpam-smbpass", reference:"2:3.5.6~dfsg-3squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"libsmbclient", reference:"2:3.5.6~dfsg-3squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"libsmbclient-dev", reference:"2:3.5.6~dfsg-3squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"libwbclient0", reference:"2:3.5.6~dfsg-3squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"samba", reference:"2:3.5.6~dfsg-3squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"samba-common", reference:"2:3.5.6~dfsg-3squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"samba-common-bin", reference:"2:3.5.6~dfsg-3squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"samba-dbg", reference:"2:3.5.6~dfsg-3squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"samba-doc", reference:"2:3.5.6~dfsg-3squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"samba-doc-pdf", reference:"2:3.5.6~dfsg-3squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"samba-tools", reference:"2:3.5.6~dfsg-3squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"smbclient", reference:"2:3.5.6~dfsg-3squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"swat", reference:"2:3.5.6~dfsg-3squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"winbind", reference:"2:3.5.6~dfsg-3squeeze5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
