#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2777. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70402);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/16 15:43:10 $");

  script_cve_id("CVE-2013-4327", "CVE-2013-4391", "CVE-2013-4394");
  script_bugtraq_id(62503, 62739, 62744);
  script_osvdb_id(97505, 98145, 98148);
  script_xref(name:"DSA", value:"2777");

  script_name(english:"Debian DSA-2777-1 : systemd - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues in systemd have been discovered by Sebastian
Krahmer and Florian Weimer: Insecure interaction with DBUS could lead
to the bypass of Policykit restrictions and privilege escalation or
denial of service through an integer overflow in journald and missing
input sanitising in the processing of X keyboard extension (XKB)
files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=725357"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/systemd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2777"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the systemd packages.

For the stable distribution (wheezy), these problems have been fixed
in version 44-11+deb7u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:systemd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/13");
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
if (deb_check(release:"7.0", prefix:"libpam-systemd", reference:"44-11+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libsystemd-daemon-dev", reference:"44-11+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libsystemd-daemon0", reference:"44-11+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libsystemd-id128-0", reference:"44-11+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libsystemd-id128-dev", reference:"44-11+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libsystemd-journal-dev", reference:"44-11+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libsystemd-journal0", reference:"44-11+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libsystemd-login-dev", reference:"44-11+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libsystemd-login0", reference:"44-11+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"systemd", reference:"44-11+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"systemd-gui", reference:"44-11+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"systemd-sysv", reference:"44-11+deb7u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
