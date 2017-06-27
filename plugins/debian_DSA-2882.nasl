#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2882. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73139);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/16 15:43:11 $");

  script_cve_id("CVE-2013-5951");
  script_bugtraq_id(66262);
  script_xref(name:"DSA", value:"2882");

  script_name(english:"Debian DSA-2882-1 : extplorer - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple cross-site scripting (XSS) vulnerabilities have been
discovered in extplorer, a web file explorer and manager using Ext JS.
A remote attacker can inject arbitrary web script or HTML code via a
crafted string in the URL to application.js.php, admin.php,
copy_move.php, functions.php, header.php and upload.php."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=741908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/extplorer"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/extplorer"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2882"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the extplorer packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 2.1.0b6+dfsg.2-1+squeeze2.

For the stable distribution (wheezy), this problem has been fixed in
version 2.1.0b6+dfsg.3-4+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:extplorer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"extplorer", reference:"2.1.0b6+dfsg.2-1+squeeze2")) flag++;
if (deb_check(release:"7.0", prefix:"extplorer", reference:"2.1.0b6+dfsg.3-4+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
