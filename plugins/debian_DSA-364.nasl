#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-364. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15201);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/12/06 20:25:09 $");

  script_cve_id("CVE-2003-0620", "CVE-2003-0645");
  script_bugtraq_id(8303, 8341);
  script_osvdb_id(10250, 10251, 10252, 10253, 11796);
  script_xref(name:"DSA", value:"364");

  script_name(english:"Debian DSA-364-3 : man-db - buffer overflows, arbitrary command execution");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"man-db provides the standard man(1) command on Debian systems. During
configuration of this package, the administrator is asked whether
man(1) should run setuid to a dedicated user ('man') in order to
provide a shared cache of preformatted manual pages. The default is
for man(1) NOT to be setuid, and in this configuration no known
vulnerability exists. However, if the user explicitly requests setuid
operation, a local attacker could exploit either of the following bugs
to execute arbitrary code as the 'man' user.

Again, these vulnerabilities do not affect the default configuration,
where man is not setuid.

  - CAN-2003-0620: Multiple buffer overflows in man-db 2.4.1
    and earlier, when installed setuid, allow local users to
    gain privileges via (1) MANDATORY_MANPATH, MANPATH_MAP,
    and MANDB_MAP arguments to add_to_dirlist in manp.c, (2)
    a long pathname to ult_src in ult_src.c, (3) a long .so
    argument to test_for_include in ult_src.c, (4) a long
    MANPATH environment variable, or (5) a long PATH
    environment variable.
  - CAN-2003-0645: Certain DEFINE directives in ~/.manpath,
    which contained commands to be executed, would be
    honored even when running setuid, allowing any user to
    execute commands as the 'man' user."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-364"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the current stable distribution (woody), these problems have been
fixed in version 2.3.20-18.woody.4.


We recommend that you update your man-db package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:man-db");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/06/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"man-db", reference:"2.3.20-18.woody.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
