#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-259. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15096);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/18 00:07:14 $");

  script_cve_id("CVE-2003-0143");
  script_osvdb_id(9794);
  script_xref(name:"DSA", value:"259");

  script_name(english:"Debian DSA-259-1 : qpopper - mail user privilege escalation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Florian Heinz posted to the Bugtraq mailing list an exploit for
qpopper based on a bug in the included vsnprintf implementation. The
sample exploit requires a valid user account and password, and
overflows a string in the pop_msg() function to give the user 'mail'
group privileges and a shell on the system. Since the Qvsnprintf
function is used elsewhere in qpopper, additional exploits may be
possible.

The qpopper package in Debian 2.2 (potato) does not include the
vulnerable snprintf implementation. For Debian 3.0 (woody) an updated
package is available in version 4.0.4-2.woody.3. Users running an
unreleased version of Debian should upgrade to 4.0.4-9 or newer. We
recommend you upgrade your qpopper package immediately."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-259"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected qpopper package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qpopper");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/03/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"qpopper", reference:"4.0.4-2.woody.3")) flag++;
if (deb_check(release:"3.0", prefix:"qpopper-drac", reference:"4.0.4-2.woody.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
