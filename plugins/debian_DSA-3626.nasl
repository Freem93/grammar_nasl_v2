#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3626. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92526);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/03/14 16:13:00 $");

  script_cve_id("CVE-2016-6210");
  script_osvdb_id(141586);
  script_xref(name:"DSA", value:"3626");

  script_name(english:"Debian DSA-3626-1 : openssh - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Eddie Harari reported that the OpenSSH SSH daemon allows user
enumeration through timing differences when trying to authenticate
users. When sshd tries to authenticate a non-existing user, it will
pick up a fixed fake password structure with a hash based on the
Blowfish algorithm. If real users passwords are hashed using
SHA256/SHA512, then a remote attacker can take advantage of this flaw
by sending large passwords, receiving shorter response times from the
server for non-existing users."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=831902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/openssh"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3626"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssh packages.

For the stable distribution (jessie), this problem has been fixed in
version 1:6.7p1-5+deb8u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"openssh-client", reference:"1:6.7p1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"openssh-client-udeb", reference:"1:6.7p1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"openssh-server", reference:"1:6.7p1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"openssh-server-udeb", reference:"1:6.7p1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"openssh-sftp-server", reference:"1:6.7p1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"ssh", reference:"1:6.7p1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"ssh-askpass-gnome", reference:"1:6.7p1-5+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"ssh-krb5", reference:"1:6.7p1-5+deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
