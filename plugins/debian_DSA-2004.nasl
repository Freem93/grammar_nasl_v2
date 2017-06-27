#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2004. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44950);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2010-0547", "CVE-2010-0787");
  script_bugtraq_id(36936, 37019, 37036, 37068, 37069, 37339, 37519, 37523, 37724, 37762, 37906, 37992, 38058, 38144, 38165, 38326);
  script_xref(name:"DSA", value:"2004");

  script_name(english:"Debian DSA-2004-1 : samba - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two local vulnerabilities have been discovered in samba, a SMB/CIFS
file, print, and login server for Unix. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2009-3297
    Ronald Volgers discovered that a race condition in
    mount.cifs allows local users to mount remote
    filesystems over arbitrary mount points.

  - CVE-2010-0547
    Jeff Layton discovered that missing input sanitising in
    mount.cifs allows denial of service by corrupting
    /etc/mtab."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2004"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the samba packages.

For the stable distribution (lenny), these problems have been fixed in
version 2:3.2.5-4lenny9."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"libpam-smbpass", reference:"2:3.2.5-4lenny9")) flag++;
if (deb_check(release:"5.0", prefix:"libsmbclient", reference:"2:3.2.5-4lenny9")) flag++;
if (deb_check(release:"5.0", prefix:"libsmbclient-dev", reference:"2:3.2.5-4lenny9")) flag++;
if (deb_check(release:"5.0", prefix:"libwbclient0", reference:"2:3.2.5-4lenny9")) flag++;
if (deb_check(release:"5.0", prefix:"samba", reference:"2:3.2.5-4lenny9")) flag++;
if (deb_check(release:"5.0", prefix:"samba-common", reference:"2:3.2.5-4lenny9")) flag++;
if (deb_check(release:"5.0", prefix:"samba-dbg", reference:"2:3.2.5-4lenny9")) flag++;
if (deb_check(release:"5.0", prefix:"samba-doc", reference:"2:3.2.5-4lenny9")) flag++;
if (deb_check(release:"5.0", prefix:"samba-doc-pdf", reference:"2:3.2.5-4lenny9")) flag++;
if (deb_check(release:"5.0", prefix:"samba-tools", reference:"2:3.2.5-4lenny9")) flag++;
if (deb_check(release:"5.0", prefix:"smbclient", reference:"2:3.2.5-4lenny9")) flag++;
if (deb_check(release:"5.0", prefix:"smbfs", reference:"2:3.2.5-4lenny9")) flag++;
if (deb_check(release:"5.0", prefix:"swat", reference:"2:3.2.5-4lenny9")) flag++;
if (deb_check(release:"5.0", prefix:"winbind", reference:"2:3.2.5-4lenny9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
