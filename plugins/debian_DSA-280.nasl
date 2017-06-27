#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-280. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15117);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/04/13 15:25:33 $");

  script_cve_id("CVE-2003-0196", "CVE-2003-0201");
  script_bugtraq_id(7294, 7295);
  script_osvdb_id(4469, 13397);
  script_xref(name:"CERT", value:"267873");
  script_xref(name:"DSA", value:"280");

  script_name(english:"Debian DSA-280-1 : samba - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Digital Defense, Inc. has alerted the Samba Team to a serious
vulnerability in Samba, a LanManager-like file and printer server for
Unix. This vulnerability can lead to an anonymous user gaining root
access on a Samba serving system. An exploit for this problem is
already circulating and in use.

Since the packages for potato are quite old it is likely that they
contain more security-relevant bugs that we don't know of. You are
therefore advised to upgrade your systems running Samba to woody soon.

Unofficial backported packages from the Samba maintainers for version
2.2.8 of Samba for woody are available at ~peloy and ~vorlon."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://people.debian.org/~peloy/samba/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://people.debian.org/~vorlon/samba/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-280"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Samba packages immediately.

For the stable distribution (woody) this problem has been fixed in
version 2.2.3a-12.3.

For the old stable distribution (potato) this problem has been fixed
in version 2.0.7-5.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba trans2open Overflow (Solaris SPARC)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/04/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"samba", reference:"2.0.7-5.1")) flag++;
if (deb_check(release:"2.2", prefix:"samba-common", reference:"2.0.7-5.1")) flag++;
if (deb_check(release:"2.2", prefix:"samba-doc", reference:"2.0.7-5.1")) flag++;
if (deb_check(release:"2.2", prefix:"smbclient", reference:"2.0.7-5.1")) flag++;
if (deb_check(release:"2.2", prefix:"smbfs", reference:"2.0.7-5.1")) flag++;
if (deb_check(release:"2.2", prefix:"swat", reference:"2.0.7-5.1")) flag++;
if (deb_check(release:"3.0", prefix:"libpam-smbpass", reference:"2.2.3a-12.3")) flag++;
if (deb_check(release:"3.0", prefix:"libsmbclient", reference:"2.2.3a-12.3")) flag++;
if (deb_check(release:"3.0", prefix:"libsmbclient-dev", reference:"2.2.3a-12.3")) flag++;
if (deb_check(release:"3.0", prefix:"samba", reference:"2.2.3a-12.3")) flag++;
if (deb_check(release:"3.0", prefix:"samba-common", reference:"2.2.3a-12.3")) flag++;
if (deb_check(release:"3.0", prefix:"samba-doc", reference:"2.2.3a-12.3")) flag++;
if (deb_check(release:"3.0", prefix:"smbclient", reference:"2.2.3a-12.3")) flag++;
if (deb_check(release:"3.0", prefix:"smbfs", reference:"2.2.3a-12.3")) flag++;
if (deb_check(release:"3.0", prefix:"swat", reference:"2.2.3a-12.3")) flag++;
if (deb_check(release:"3.0", prefix:"winbind", reference:"2.2.3a-12.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
