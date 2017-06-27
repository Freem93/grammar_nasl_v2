#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2463. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58969);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/02/16 15:37:38 $");

  script_cve_id("CVE-2012-2111");
  script_bugtraq_id(53307);
  script_osvdb_id(81648);
  script_xref(name:"DSA", value:"2463");

  script_name(english:"Debian DSA-2463-1 : samba - missing permission checks");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ivano Cristofolini discovered that insufficient security checks in
Samba's handling of LSA RPC calls could lead to privilege escalation
by gaining the 'take ownership' privilege."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/samba"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2463"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the samba packages.

For the stable distribution (squeeze), this problem has been fixed in
version 3.5.6~dfsg-3squeeze8."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libpam-smbpass", reference:"3.5.6~dfsg-3squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"libsmbclient", reference:"3.5.6~dfsg-3squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"libsmbclient-dev", reference:"3.5.6~dfsg-3squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"libwbclient0", reference:"3.5.6~dfsg-3squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"samba", reference:"3.5.6~dfsg-3squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"samba-common", reference:"3.5.6~dfsg-3squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"samba-common-bin", reference:"3.5.6~dfsg-3squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"samba-dbg", reference:"3.5.6~dfsg-3squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"samba-doc", reference:"3.5.6~dfsg-3squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"samba-doc-pdf", reference:"3.5.6~dfsg-3squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"samba-tools", reference:"3.5.6~dfsg-3squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"smbclient", reference:"3.5.6~dfsg-3squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"swat", reference:"3.5.6~dfsg-3squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"winbind", reference:"3.5.6~dfsg-3squeeze8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
