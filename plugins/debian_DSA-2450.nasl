#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2450. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58729);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2012-1182");
  script_bugtraq_id(52973);
  script_osvdb_id(81303);
  script_xref(name:"DSA", value:"2450");

  script_name(english:"Debian DSA-2450-1 : samba - privilege escalation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Samba, the SMB/CIFS file, print, and login
server, contained a flaw in the remote procedure call (RPC) code which
allowed remote code execution as the super user from an
unauthenticated connection."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=668309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/samba"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2450"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the samba packages.

For the stable distribution (squeeze), this problem has been fixed in
version 2:3.5.6~dfsg-3squeeze7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba SetInformationPolicy AuditEventsInfo Heap Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libpam-smbpass", reference:"2:3.5.6~dfsg-3squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libsmbclient", reference:"2:3.5.6~dfsg-3squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libsmbclient-dev", reference:"2:3.5.6~dfsg-3squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libwbclient0", reference:"2:3.5.6~dfsg-3squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"samba", reference:"2:3.5.6~dfsg-3squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"samba-common", reference:"2:3.5.6~dfsg-3squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"samba-common-bin", reference:"2:3.5.6~dfsg-3squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"samba-dbg", reference:"2:3.5.6~dfsg-3squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"samba-doc", reference:"2:3.5.6~dfsg-3squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"samba-doc-pdf", reference:"2:3.5.6~dfsg-3squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"samba-tools", reference:"2:3.5.6~dfsg-3squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"smbclient", reference:"2:3.5.6~dfsg-3squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"swat", reference:"2:3.5.6~dfsg-3squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"winbind", reference:"2:3.5.6~dfsg-3squeeze7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
