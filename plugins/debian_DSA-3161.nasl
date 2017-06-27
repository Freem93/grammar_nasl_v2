#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3161. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81302);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/05 16:01:11 $");

  script_cve_id("CVE-2015-0245");
  script_bugtraq_id(72545);
  script_osvdb_id(118407);
  script_xref(name:"DSA", value:"3161");

  script_name(english:"Debian DSA-3161-1 : dbus - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Simon McVittie discovered a local denial of service flaw in dbus, an
asynchronous inter-process communication system. On systems with
systemd-style service activation, dbus-daemon does not prevent forged
ActivationFailure messages from non-root processes. A malicious local
user could use this flaw to trick dbus-daemon into thinking that
systemd failed to activate a system service, resulting in an error
reply back to the requester."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=777545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/dbus"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3161"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the dbus packages.

For the stable distribution (wheezy), this problem has been fixed in
version 1.6.8-1+deb7u6."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dbus");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"dbus", reference:"1.6.8-1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"dbus-1-dbg", reference:"1.6.8-1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"dbus-1-doc", reference:"1.6.8-1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"dbus-x11", reference:"1.6.8-1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libdbus-1-3", reference:"1.6.8-1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libdbus-1-dev", reference:"1.6.8-1+deb7u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
