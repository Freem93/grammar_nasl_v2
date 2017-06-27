#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2109. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49275);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2010-3069");
  script_bugtraq_id(43212);
  script_xref(name:"DSA", value:"2109");

  script_name(english:"Debian DSA-2109-1 : samba - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability has been discovered in samba, a SMB/CIFS file, print,
and login server for Unix.

The sid_parse() function does not correctly check its input lengths
when reading a binary representation of a Windows SID (Security ID).
This allows a malicious client to send a sid that can overflow the
stack variable that is being used to store the SID in the Samba smbd
server. (CVE-2010-3069 )"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=596891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2109"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the samba packages. The packages for the mips architecture are
not included in this upgrade. They will be released as soon as they
become available.

For the stable distribution (lenny), this problem has been fixed in
version 3.2.5-4lenny13."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/20");
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
if (deb_check(release:"5.0", prefix:"libpam-smbpass", reference:"3.2.5-4lenny13")) flag++;
if (deb_check(release:"5.0", prefix:"libsmbclient", reference:"3.2.5-4lenny13")) flag++;
if (deb_check(release:"5.0", prefix:"libsmbclient-dev", reference:"3.2.5-4lenny13")) flag++;
if (deb_check(release:"5.0", prefix:"libwbclient0", reference:"3.2.5-4lenny13")) flag++;
if (deb_check(release:"5.0", prefix:"samba", reference:"3.2.5-4lenny13")) flag++;
if (deb_check(release:"5.0", prefix:"samba-common", reference:"3.2.5-4lenny13")) flag++;
if (deb_check(release:"5.0", prefix:"samba-dbg", reference:"3.2.5-4lenny13")) flag++;
if (deb_check(release:"5.0", prefix:"samba-doc", reference:"3.2.5-4lenny13")) flag++;
if (deb_check(release:"5.0", prefix:"samba-doc-pdf", reference:"3.2.5-4lenny13")) flag++;
if (deb_check(release:"5.0", prefix:"samba-tools", reference:"3.2.5-4lenny13")) flag++;
if (deb_check(release:"5.0", prefix:"smbclient", reference:"3.2.5-4lenny13")) flag++;
if (deb_check(release:"5.0", prefix:"smbfs", reference:"3.2.5-4lenny13")) flag++;
if (deb_check(release:"5.0", prefix:"swat", reference:"3.2.5-4lenny13")) flag++;
if (deb_check(release:"5.0", prefix:"winbind", reference:"3.2.5-4lenny13")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
