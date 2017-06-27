#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2614. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64395);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/03/14 16:13:00 $");

  script_cve_id("CVE-2012-5958", "CVE-2012-5959", "CVE-2012-5960", "CVE-2012-5961", "CVE-2012-5962", "CVE-2012-5963", "CVE-2012-5964", "CVE-2012-5965");
  script_bugtraq_id(57602);
  script_osvdb_id(89611, 90578, 97337, 97338);
  script_xref(name:"DSA", value:"2614");
  script_xref(name:"TRA", value:"TRA-2017-10");

  script_name(english:"Debian DSA-2614-1 : libupnp - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple stack-based buffer overflows were discovered in libupnp, a
library used for handling the Universal Plug and Play protocol. HD
Moore from Rapid7 discovered that SSDP queries where not correctly
handled by the unique_service_name() function.

An attacker sending carefully crafted SSDP queries to a daemon built
on libupnp could generate a buffer overflow, overwriting the stack,
leading to the daemon crash and possible remote code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=699316"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/libupnp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2017-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libupnp packages.

For the stable distribution (squeeze), these problems have been fixed
in version 1:1.6.6-5+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Portable UPnP SDK unique_service_name() Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libupnp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libupnp-dev", reference:"1:1.6.6-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libupnp3", reference:"1:1.6.6-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libupnp3-dbg", reference:"1:1.6.6-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libupnp3-dev", reference:"1:1.6.6-5+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
