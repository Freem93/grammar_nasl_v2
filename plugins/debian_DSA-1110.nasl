#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1110. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22652);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/05/17 23:36:52 $");

  script_cve_id("CVE-2006-3403");
  script_osvdb_id(27130);
  script_xref(name:"DSA", value:"1110");

  script_name(english:"Debian DSA-1110-1 : samba - missing input sanitising");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Gerald Carter discovered that the smbd daemon from Samba, a free
implementation of the SMB/CIFS protocol, imposes insufficient limits
in the code to handle shared connections, which can be exploited to
exhaust system memory by sending maliciously crafted requests, leading
to denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1110"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the samba package.

For the stable distribution (sarge) this problem has been fixed in
version 3.0.14a-3sarge2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libpam-smbpass", reference:"3.0.14a-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libsmbclient", reference:"3.0.14a-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libsmbclient-dev", reference:"3.0.14a-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"python2.3-samba", reference:"3.0.14a-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"samba", reference:"3.0.14a-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"samba-common", reference:"3.0.14a-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"samba-dbg", reference:"3.0.14a-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"samba-doc", reference:"3.0.14a-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"smbclient", reference:"3.0.14a-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"smbfs", reference:"3.0.14a-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"swat", reference:"3.0.14a-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"winbind", reference:"3.0.14a-3sarge2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
