#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3487. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88915);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/10 14:14:52 $");

  script_cve_id("CVE-2016-0787");
  script_xref(name:"DSA", value:"3487");

  script_name(english:"Debian DSA-3487-1 : libssh2 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Andreas Schneider reported that libssh2, a SSH2 client-side library,
passes the number of bytes to a function that expects number of bits
during the SSHv2 handshake when libssh2 is to get a suitable value
for'group order' in the Diffie-Hellman negotiation. This weakens
significantly the handshake security, potentially allowing an
eavesdropper with enough resources to decrypt or intercept SSH
sessions."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=815662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libssh2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libssh2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3487"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libssh2 packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 1.4.2-1.1+deb7u2.

For the stable distribution (jessie), this problem has been fixed in
version 1.4.3-4.1+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssh2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libssh2-1", reference:"1.4.2-1.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libssh2-1-dbg", reference:"1.4.2-1.1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libssh2-1-dev", reference:"1.4.2-1.1+deb7u2")) flag++;
if (deb_check(release:"8.0", prefix:"libssh2-1", reference:"1.4.3-4.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libssh2-1-dbg", reference:"1.4.3-4.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libssh2-1-dev", reference:"1.4.3-4.1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
