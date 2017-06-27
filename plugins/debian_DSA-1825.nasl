#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1825. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44690);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/03/30 13:45:22 $");

  script_cve_id("CVE-2009-2288");
  script_bugtraq_id(35464);
  script_osvdb_id(55281);
  script_xref(name:"DSA", value:"1825");

  script_name(english:"Debian DSA-1825-1 : nagios2, nagios3 - insufficient input validation");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the statuswml.cgi script of nagios, a
monitoring and management system for hosts, services and networks, is
prone to a command injection vulnerability. Input to the ping and
traceroute parameters of the script is not properly validated which
allows an attacker to execute arbitrary shell commands by passing a
crafted value to these parameters."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1825"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the nagios2/nagios3 packages.

For the oldstable distribution (etch), this problem has been fixed in
version 2.6-2+etch3 of nagios2.

For the stable distribution (lenny), this problem has been fixed in
version 3.0.6-4~lenny2 of nagios3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Nagios 3.1.0 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Nagios3 statuswml.cgi Ping Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(78);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nagios2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nagios3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"nagios2", reference:"2.6-2+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"nagios2-common", reference:"2.6-2+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"nagios2-dbg", reference:"2.6-2+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"nagios2-doc", reference:"2.6-2+etch3")) flag++;
if (deb_check(release:"5.0", prefix:"nagios3", reference:"3.0.6-4~lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"nagios3-common", reference:"3.0.6-4~lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"nagios3-dbg", reference:"3.0.6-4~lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"nagios3-doc", reference:"3.0.6-4~lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
