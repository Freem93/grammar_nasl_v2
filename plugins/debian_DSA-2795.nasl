#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2795. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70982);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/16 15:43:10 $");

  script_cve_id("CVE-2013-4508", "CVE-2013-4559", "CVE-2013-4560");
  script_bugtraq_id(63534, 63686, 63688);
  script_xref(name:"DSA", value:"2795");

  script_name(english:"Debian DSA-2795-2 : lighttpd - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the lighttpd web
server.

It was discovered that SSL connections with client certificates
stopped working after the DSA-2795-1 update of lighttpd. An upstream
patch has now been applied that provides an appropriate identifier for
client certificate verification.

  - CVE-2013-4508
    It was discovered that lighttpd uses weak ssl ciphers
    when SNI (Server Name Indication) is enabled. This issue
    was solved by ensuring that stronger ssl ciphers are
    used when SNI is selected.

  - CVE-2013-4559
    The clang static analyzer was used to discover privilege
    escalation issues due to missing checks around
    lighttpd's setuid, setgid, and setgroups calls. Those
    are now appropriately checked.

  - CVE-2013-4560
    The clang static analyzer was used to discover a
    use-after-free issue when the FAM stat cache engine is
    enabled, which is now fixed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=729453"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=729480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4508"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4559"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4560"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/lighttpd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/lighttpd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2795"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the lighttpd packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 1.4.28-2+squeeze1.5.

For the stable distribution (wheezy), these problems have been fixed
in version 1.4.31-4+deb7u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"lighttpd", reference:"1.4.28-2+squeeze1.5")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-doc", reference:"1.4.28-2+squeeze1.5")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-mod-cml", reference:"1.4.28-2+squeeze1.5")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-mod-magnet", reference:"1.4.28-2+squeeze1.5")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-mod-mysql-vhost", reference:"1.4.28-2+squeeze1.5")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-mod-trigger-b4-dl", reference:"1.4.28-2+squeeze1.5")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-mod-webdav", reference:"1.4.28-2+squeeze1.5")) flag++;
if (deb_check(release:"7.0", prefix:"lighttpd", reference:"1.4.31-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"lighttpd-doc", reference:"1.4.31-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"lighttpd-mod-cml", reference:"1.4.31-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"lighttpd-mod-magnet", reference:"1.4.31-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"lighttpd-mod-mysql-vhost", reference:"1.4.31-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"lighttpd-mod-trigger-b4-dl", reference:"1.4.31-4+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"lighttpd-mod-webdav", reference:"1.4.31-4+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
