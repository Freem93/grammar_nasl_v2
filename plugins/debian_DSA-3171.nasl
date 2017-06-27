#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3171. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81450);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/01/10 05:42:14 $");

  script_cve_id("CVE-2015-0240");
  script_xref(name:"DSA", value:"3171");

  script_name(english:"Debian DSA-3171-1 : samba - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Richard van Eeden of Microsoft Vulnerability Research discovered that
Samba, a SMB/CIFS file, print, and login server for Unix, contains a
flaw in the netlogon server code which allows remote code execution
with root privileges from an unauthenticated connection."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/samba"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3171"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the samba packages.

For the stable distribution (wheezy), this problem has been fixed in
version 2:3.6.6-6+deb7u5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libnss-winbind", reference:"2:3.6.6-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libpam-smbpass", reference:"2:3.6.6-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libpam-winbind", reference:"2:3.6.6-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libsmbclient", reference:"2:3.6.6-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libsmbclient-dev", reference:"2:3.6.6-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libwbclient-dev", reference:"2:3.6.6-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libwbclient0", reference:"2:3.6.6-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"samba", reference:"2:3.6.6-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"samba-common", reference:"2:3.6.6-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"samba-common-bin", reference:"2:3.6.6-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"samba-dbg", reference:"2:3.6.6-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"samba-doc", reference:"2:3.6.6-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"samba-doc-pdf", reference:"2:3.6.6-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"samba-tools", reference:"2:3.6.6-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"smbclient", reference:"2:3.6.6-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"swat", reference:"2:3.6.6-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"winbind", reference:"2:3.6.6-6+deb7u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
