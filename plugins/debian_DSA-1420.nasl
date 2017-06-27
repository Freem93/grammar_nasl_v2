#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1420. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29227);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/03/30 13:45:22 $");

  script_cve_id("CVE-2007-6210");
  script_bugtraq_id(26680);
  script_osvdb_id(42480);
  script_xref(name:"DSA", value:"1420");

  script_name(english:"Debian DSA-1420-1 : zabbix - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Bas van Schaik discovered that the agentd process of Zabbix, a network
monitor system, may run user-supplied commands as group id root, not
zabbix, which may lead to a privilege escalation.

zabbix is not included in the oldstable distribution (sarge)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=452682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1420"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the zabbix packages.

For the stable distribution (etch), this problem has been fixed in
version 1:1.1.4-10etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"zabbix-agent", reference:"1:1.1.4-10etch1")) flag++;
if (deb_check(release:"4.0", prefix:"zabbix-frontend-php", reference:"1:1.1.4-10etch1")) flag++;
if (deb_check(release:"4.0", prefix:"zabbix-server-mysql", reference:"1:1.1.4-10etch1")) flag++;
if (deb_check(release:"4.0", prefix:"zabbix-server-pgsql", reference:"1:1.1.4-10etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
