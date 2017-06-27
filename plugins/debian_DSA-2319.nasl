#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2319. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56414);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/02/16 15:31:56 $");

  script_cve_id("CVE-2011-1485");
  script_bugtraq_id(47496);
  script_osvdb_id(72261);
  script_xref(name:"DSA", value:"2319");

  script_name(english:"Debian DSA-2319-1 : policykit-1 - race condition");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Neel Mehta discovered that a race condition in Policykit, a framework
for managing administrative policies and privileges, allowed local
users to elevate privileges by executing a setuid program from pkexec.

The oldstable distribution (lenny) does not contain the policykit-1
package."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=644500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/policykit-1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2319"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the policykit-1 packages.

For the stable distribution (squeeze), this problem has been fixed in
version 0.96-4+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux PolicyKit Race Condition Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:policykit-1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libpolkit-agent-1-0", reference:"0.96-4+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libpolkit-agent-1-dev", reference:"0.96-4+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libpolkit-backend-1-0", reference:"0.96-4+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libpolkit-backend-1-dev", reference:"0.96-4+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libpolkit-gobject-1-0", reference:"0.96-4+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libpolkit-gobject-1-dev", reference:"0.96-4+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"policykit-1", reference:"0.96-4+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"policykit-1-doc", reference:"0.96-4+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
