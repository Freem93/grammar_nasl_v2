#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3550. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90550);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2015-8325");
  script_osvdb_id(137226);
  script_xref(name:"DSA", value:"3550");

  script_name(english:"Debian DSA-3550-1 : openssh - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Shayan Sadigh discovered a vulnerability in OpenSSH: If PAM support is
enabled and the sshd PAM configuration is configured to read
userspecified environment variables and the 'UseLogin' option is
enabled, a local user may escalate her privileges to root.

In Debian 'UseLogin' is not enabled by default."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/openssh"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/openssh"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3550"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssh packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 6.0p1-4+deb7u4.

For the stable distribution (jessie), this problem has been fixed in
version 6.7p1-5+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/18");
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
if (deb_check(release:"7.0", prefix:"openssh-client", reference:"6.0p1-4+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"openssh-client-udeb", reference:"6.0p1-4+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"openssh-server", reference:"6.0p1-4+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"openssh-server-udeb", reference:"6.0p1-4+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"ssh", reference:"6.0p1-4+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"ssh-askpass-gnome", reference:"6.0p1-4+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"ssh-krb5", reference:"6.0p1-4+deb7u4")) flag++;
if (deb_check(release:"8.0", prefix:"openssh-client", reference:"6.7p1-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"openssh-client-udeb", reference:"6.7p1-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"openssh-server", reference:"6.7p1-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"openssh-server-udeb", reference:"6.7p1-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"openssh-sftp-server", reference:"6.7p1-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ssh", reference:"6.7p1-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ssh-askpass-gnome", reference:"6.7p1-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ssh-krb5", reference:"6.7p1-5+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
