#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2894. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73350);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2014-2532", "CVE-2014-2653");
  script_bugtraq_id(66355, 66459);
  script_xref(name:"DSA", value:"2894");

  script_name(english:"Debian DSA-2894-1 : openssh - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were discovered in OpenSSH, an implementation of
the SSH protocol suite. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2014-2532
    Jann Horn discovered that OpenSSH incorrectly handled
    wildcards in AcceptEnv lines. A remote attacker could
    use this issue to trick OpenSSH into accepting any
    environment variable that contains the characters before
    the wildcard character.

  - CVE-2014-2653
    Matthew Vernon reported that if a SSH server offers a
    HostCertificate that the ssh client doesn't accept, then
    the client doesn't check the DNS for SSHFP records. As a
    consequence a malicious server can disable
    SSHFP-checking by presenting a certificate.

  Note that a host verification prompt is still displayed before
  connecting."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=742513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-2532"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-2653"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/openssh"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/openssh"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2894"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssh packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 1:5.5p1-6+squeeze5.

For the stable distribution (wheezy), these problems have been fixed
in version 1:6.0p1-4+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"openssh-client", reference:"1:5.5p1-6+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"openssh-client-udeb", reference:"1:5.5p1-6+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"openssh-server", reference:"1:5.5p1-6+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"openssh-server-udeb", reference:"1:5.5p1-6+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"ssh", reference:"1:5.5p1-6+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"ssh-askpass-gnome", reference:"1:5.5p1-6+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"ssh-krb5", reference:"1:5.5p1-6+squeeze5")) flag++;
if (deb_check(release:"7.0", prefix:"openssh-client", reference:"1:6.0p1-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openssh-client-udeb", reference:"1:6.0p1-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openssh-server", reference:"1:6.0p1-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openssh-server-udeb", reference:"1:6.0p1-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ssh", reference:"1:6.0p1-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ssh-askpass-gnome", reference:"1:6.0p1-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ssh-krb5", reference:"1:6.0p1-4+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
