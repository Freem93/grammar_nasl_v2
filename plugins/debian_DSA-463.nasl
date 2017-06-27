#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-463. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15300);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/05/18 00:11:35 $");

  script_cve_id("CVE-2004-0186");
  script_bugtraq_id(9619);
  script_xref(name:"DSA", value:"463");

  script_name(english:"Debian DSA-463-1 : samba - privilege escalation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Samba, a LanManager-like file and printer server for Unix, was found
to contain a vulnerability whereby a local user could use the 'smbmnt'
utility, which is setuid root, to mount a file share from a remote
server which contained setuid programs under the control of the user.
These programs could then be executed to gain privileges on the local
system."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-463"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the current stable distribution (woody) this problem has been
fixed in version 2.2.3a-13.

We recommend that you update your samba package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/03/12");
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
if (deb_check(release:"3.0", prefix:"libpam-smbpass", reference:"2.2.3a-13")) flag++;
if (deb_check(release:"3.0", prefix:"libsmbclient", reference:"2.2.3a-13")) flag++;
if (deb_check(release:"3.0", prefix:"libsmbclient-dev", reference:"2.2.3a-13")) flag++;
if (deb_check(release:"3.0", prefix:"samba", reference:"2.2.3a-13")) flag++;
if (deb_check(release:"3.0", prefix:"samba-common", reference:"2.2.3a-13")) flag++;
if (deb_check(release:"3.0", prefix:"samba-doc", reference:"2.2.3a-13")) flag++;
if (deb_check(release:"3.0", prefix:"smbclient", reference:"2.2.3a-13")) flag++;
if (deb_check(release:"3.0", prefix:"smbfs", reference:"2.2.3a-13")) flag++;
if (deb_check(release:"3.0", prefix:"swat", reference:"2.2.3a-13")) flag++;
if (deb_check(release:"3.0", prefix:"winbind", reference:"2.2.3a-13")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
