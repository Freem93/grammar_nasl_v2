#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3488. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88916);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/10 14:14:52 $");

  script_cve_id("CVE-2016-0739");
  script_xref(name:"DSA", value:"3488");

  script_name(english:"Debian DSA-3488-1 : libssh - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Aris Adamantiadis discovered that libssh, a tiny C SSH library,
incorrectly generated a short ephemeral secret for the
diffie-hellman-group1 and diffie-hellman-group14 key exchange methods.
The resulting secret is 128 bits long, instead of the recommended
sizes of 1024 and 2048 bits respectively. This flaw could allow an
eavesdropper with enough resources to decrypt or intercept SSH
sessions."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=815663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-8132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3146"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libssh"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libssh"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3488"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libssh packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 0.5.4-1+deb7u3. This update also includes fixes for
CVE-2014-8132 and CVE-2015-3146, which were previously scheduled for
the next wheezy point release.

For the stable distribution (jessie), this problem has been fixed in
version 0.6.3-4+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssh");
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
if (deb_check(release:"7.0", prefix:"libssh-4", reference:"0.5.4-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libssh-dbg", reference:"0.5.4-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libssh-dev", reference:"0.5.4-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libssh-doc", reference:"0.5.4-1+deb7u3")) flag++;
if (deb_check(release:"8.0", prefix:"libssh-4", reference:"0.6.3-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libssh-dbg", reference:"0.6.3-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libssh-dev", reference:"0.6.3-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libssh-doc", reference:"0.6.3-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libssh-gcrypt-4", reference:"0.6.3-4+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libssh-gcrypt-dev", reference:"0.6.3-4+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
