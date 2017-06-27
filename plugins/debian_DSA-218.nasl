#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-218. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15055);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2014/08/14 14:19:28 $");

  script_cve_id("CVE-2002-2260");
  script_bugtraq_id(6257);
  script_osvdb_id(6401);
  script_xref(name:"DSA", value:"218");

  script_name(english:"Debian DSA-218-1 : bugzilla - XSS");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A cross site scripting vulnerability has been reported for Bugzilla, a
web-based bug tracking system. Bugzilla does not properly sanitize any
input submitted by users for use in quips. As a result, it is possible
for a remote attacker to create a malicious link containing script
code which will be executed in the browser of a legitimate user, in
the context of the website running Bugzilla. This issue may be
exploited to steal cookie-based authentication credentials from
legitimate users of the website running the vulnerable software.

This vulnerability only affects users who have the 'quips' feature
enabled and who upgraded from version 2.10 which did not exist inside
of Debian. The Debian package history of Bugzilla starts with 1.13 and
jumped to 2.13. However, users could have installed version 2.10 prior
to the Debian package."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-218"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bugzilla packages.

For the current stable distribution (woody) this problem has been
fixed in version 2.14.2-0woody3.

The old stable distribution (potato) does not contain a Bugzilla
package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bugzilla");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/12/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/11/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"bugzilla", reference:"2.14.2-0woody3")) flag++;
if (deb_check(release:"3.0", prefix:"bugzilla-doc", reference:"2.14.2-0woody3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
