#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1772. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36172);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2009-1185", "CVE-2009-1186");
  script_bugtraq_id(34536, 34539);
  script_osvdb_id(53810, 53811);
  script_xref(name:"DSA", value:"1772");

  script_name(english:"Debian DSA-1772-1 : udev - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sebastian Kramer discovered two vulnerabilities in udev, the /dev and
hotplug management daemon.

  - CVE-2009-1185
    udev does not check the origin of NETLINK messages,
    allowing local users to gain root privileges.

  - CVE-2009-1186
    udev suffers from a buffer overflow condition in path
    encoding, potentially allowing arbitrary code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1772"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the udev package.

For the old stable distribution (etch), these problems have been fixed
in version 0.105-4etch1.

For the stable distribution (lenny), these problems have been fixed in
version 0.125-7+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux udev Netlink Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/17");
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
if (deb_check(release:"4.0", prefix:"libvolume-id-dev", reference:"0.105-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libvolume-id0", reference:"0.105-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"udev", reference:"0.105-4etch1")) flag++;
if (deb_check(release:"5.0", prefix:"libvolume-id-dev", reference:"0.125-7+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libvolume-id0", reference:"0.125-7+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"udev", reference:"0.125-7+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
