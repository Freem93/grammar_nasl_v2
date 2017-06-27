#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1823. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39568);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/06 20:12:52 $");

  script_cve_id("CVE-2009-1886", "CVE-2009-1888");
  script_xref(name:"DSA", value:"1823");

  script_name(english:"Debian DSA-1823-1 : samba - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Samba, a SMB/CIFS
file, print, and login server. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2009-1886
    The smbclient utility contains a formatstring
    vulnerability where commands dealing with file names
    treat user input as format strings to asprintf.

  - CVE-2009-1888
    In the smbd daemon, if a user is trying to modify an
    access control list (ACL) and is denied permission, this
    deny may be overridden if the parameter 'dos filemode'
    is set to 'yes' in the smb.conf and the user already has
    write access to the file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1823"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the samba package.

The old stable distribution (etch) is not affected by these problems.

For the stable distribution (lenny), these problems have been fixed in
version 3.2.5-4lenny6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(134, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"libpam-smbpass", reference:"3.2.5-4lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libsmbclient", reference:"3.2.5-4lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libsmbclient-dev", reference:"3.2.5-4lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libwbclient0", reference:"3.2.5-4lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"samba", reference:"3.2.5-4lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"samba-common", reference:"3.2.5-4lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"samba-dbg", reference:"3.2.5-4lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"samba-doc", reference:"3.2.5-4lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"samba-doc-pdf", reference:"3.2.5-4lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"samba-tools", reference:"3.2.5-4lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"smbclient", reference:"3.2.5-4lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"smbfs", reference:"3.2.5-4lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"swat", reference:"3.2.5-4lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"winbind", reference:"3.2.5-4lenny6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
