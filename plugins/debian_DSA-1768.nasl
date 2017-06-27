#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1768. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36135);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2009-1250", "CVE-2009-1251");
  script_bugtraq_id(34404, 34407);
  script_osvdb_id(55273, 55274);
  script_xref(name:"DSA", value:"1768");

  script_name(english:"Debian DSA-1768-1 : openafs - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were discovered in the client part of OpenAFS, a
distributed file system.

  - CVE-2009-1251
    An attacker with control of a file server or the ability
    to forge RX packets may be able to execute arbitrary
    code in kernel mode on an OpenAFS client, due to a
    vulnerability in XDR array decoding.

  - CVE-2009-1250
    An attacker with control of a file server or the ability
    to forge RX packets may crash OpenAFS clients because of
    wrongly handled error return codes in the kernel module.

Note that in order to apply this security update, you must rebuild the
OpenAFS kernel module. Be sure to also upgrade openafs-modules-source,
build a new kernel module for your system following the instructions
in /usr/share/doc/openafs-client/README.modules.gz, and then either
stop and restart openafs-client or reboot the system to reload the
kernel module."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1250"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1768"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openafs packages.

For the old stable distribution (etch), these problems have been fixed
in version 1.4.2-6etch2.

For the stable distribution (lenny), these problems have been fixed in
version 1.4.7.dfsg1-6+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/11");
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
if (deb_check(release:"4.0", prefix:"libopenafs-dev", reference:"1.4.2-6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libpam-openafs-kaserver", reference:"1.4.2-6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"openafs-client", reference:"1.4.2-6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"openafs-dbg", reference:"1.4.2-6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"openafs-dbserver", reference:"1.4.2-6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"openafs-doc", reference:"1.4.2-6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"openafs-fileserver", reference:"1.4.2-6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"openafs-kpasswd", reference:"1.4.2-6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"openafs-krb5", reference:"1.4.2-6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"openafs-modules-source", reference:"1.4.2-6etch2")) flag++;
if (deb_check(release:"5.0", prefix:"libopenafs-dev", reference:"1.4.7.dfsg1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libpam-openafs-kaserver", reference:"1.4.7.dfsg1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"openafs-client", reference:"1.4.7.dfsg1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"openafs-dbg", reference:"1.4.7.dfsg1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"openafs-dbserver", reference:"1.4.7.dfsg1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"openafs-doc", reference:"1.4.7.dfsg1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"openafs-fileserver", reference:"1.4.7.dfsg1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"openafs-kpasswd", reference:"1.4.7.dfsg1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"openafs-krb5", reference:"1.4.7.dfsg1-6+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"openafs-modules-source", reference:"1.4.7.dfsg1-6+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
