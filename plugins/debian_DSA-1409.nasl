#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1409. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28298);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2007-4572", "CVE-2007-5398");
  script_osvdb_id(39179, 39180);
  script_xref(name:"DSA", value:"1409");

  script_name(english:"Debian DSA-1409-3 : samba - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes all currently known regressions introduced with the
previous two revisions of DSA-1409. The original text is reproduced
below :

  Several local/remote vulnerabilities have been discovered in samba,
  a LanManager-like file and printer server for Unix. The Common
  Vulnerabilities and Exposures project identifies the following
  problems :

    - CVE-2007-5398
      Alin Rad Pop of Secunia Research discovered that nmbd
      did not properly check the length of netbios packets.
      When samba is configured as a WINS server, a remote
      attacker could send multiple crafted requests
      resulting in the execution of arbitrary code with root
      privileges.

    - CVE-2007-4572
      Samba developers discovered that nmbd could be made to
      overrun a buffer during the processing of GETDC logon
      server requests. When samba is configured as a Primary
      or Backup Domain Controller, a remote attacker could
      send malicious logon requests and possibly cause a
      denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5398"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1409"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the samba packages.

For the old stable distribution (sarge), these problems have been
fixed in version 3.0.14a-3sarge10.

For the stable distribution (etch), these problems have been fixed in
version 3.0.24-6etch8."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libpam-smbpass", reference:"3.0.14a-3sarge10")) flag++;
if (deb_check(release:"3.1", prefix:"libsmbclient", reference:"3.0.14a-3sarge10")) flag++;
if (deb_check(release:"3.1", prefix:"libsmbclient-dev", reference:"3.0.14a-3sarge10")) flag++;
if (deb_check(release:"3.1", prefix:"python2.3-samba", reference:"3.0.14a-3sarge10")) flag++;
if (deb_check(release:"3.1", prefix:"samba", reference:"3.0.14a-3sarge10")) flag++;
if (deb_check(release:"3.1", prefix:"samba-common", reference:"3.0.14a-3sarge10")) flag++;
if (deb_check(release:"3.1", prefix:"samba-dbg", reference:"3.0.14a-3sarge10")) flag++;
if (deb_check(release:"3.1", prefix:"samba-doc", reference:"3.0.14a-3sarge10")) flag++;
if (deb_check(release:"3.1", prefix:"smbclient", reference:"3.0.14a-3sarge10")) flag++;
if (deb_check(release:"3.1", prefix:"smbfs", reference:"3.0.14a-3sarge10")) flag++;
if (deb_check(release:"3.1", prefix:"swat", reference:"3.0.14a-3sarge10")) flag++;
if (deb_check(release:"3.1", prefix:"winbind", reference:"3.0.14a-3sarge10")) flag++;
if (deb_check(release:"4.0", prefix:"libpam-smbpass", reference:"3.0.24-6etch8")) flag++;
if (deb_check(release:"4.0", prefix:"libsmbclient", reference:"3.0.24-6etch8")) flag++;
if (deb_check(release:"4.0", prefix:"libsmbclient-dev", reference:"3.0.24-6etch8")) flag++;
if (deb_check(release:"4.0", prefix:"python-samba", reference:"3.0.24-6etch8")) flag++;
if (deb_check(release:"4.0", prefix:"samba", reference:"3.0.24-6etch8")) flag++;
if (deb_check(release:"4.0", prefix:"samba-common", reference:"3.0.24-6etch8")) flag++;
if (deb_check(release:"4.0", prefix:"samba-dbg", reference:"3.0.24-6etch8")) flag++;
if (deb_check(release:"4.0", prefix:"samba-doc", reference:"3.0.24-6etch8")) flag++;
if (deb_check(release:"4.0", prefix:"samba-doc-pdf", reference:"3.0.24-6etch8")) flag++;
if (deb_check(release:"4.0", prefix:"smbclient", reference:"3.0.24-6etch8")) flag++;
if (deb_check(release:"4.0", prefix:"smbfs", reference:"3.0.24-6etch8")) flag++;
if (deb_check(release:"4.0", prefix:"swat", reference:"3.0.24-6etch8")) flag++;
if (deb_check(release:"4.0", prefix:"winbind", reference:"3.0.24-6etch8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
