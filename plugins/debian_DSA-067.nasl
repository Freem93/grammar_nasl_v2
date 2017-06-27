#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-067. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14904);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2013/05/17 23:36:50 $");

  script_cve_id("CVE-2001-0925");
  script_bugtraq_id(2503);
  script_osvdb_id(9698, 9699, 9700);
  script_xref(name:"DSA", value:"067");

  script_name(english:"Debian DSA-067-1 : apache - Remote exploit");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"We have received reports that the `apache' package, as included in
 the Debian `stable' distribution, is vulnerable to the `artificially
 long slash path directory listing vulnerability' as described on
 SecurityFocus.

This vulnerability was announced to bugtraq by Dan Harkless.

Quoting the SecurityFocus entry for this vulnerability :

  A problem in the package could allow directory indexing, and path
  discovery. In a default configuration, Apache enables mod_dir,
  mod_autoindex, and mod_negotiation. However, by placing a custom
  crafted request to the Apache server consisting of a long path name
  created artificially by using numerous slashes, this can cause these
  modules to misbehave, making it possible to escape the error page,
  and gain a listing of the directory contents.

  This vulnerability makes it possible for a malicious remote user to
  launch an information gathering attack, which could potentially
  result in compromise of the system. Additionally, this vulnerability
  affects all releases of Apache previous to 1.3.19."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/vdb/bottom.html?vid=2503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2001/dsa-067"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"This problem has been fixed in apache-ssl 1.3.9-13.3 and apache
1.3.9-14. We recommend that you upgrade your packages immediately.

Warning: The MD5Sum of the .dsc and .diff.gz file don't match since
they were copied from the stable release afterwards, the content of
the .diff.gz file is the same, though, checked."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache-ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2001/03/12");
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
if (deb_check(release:"2.2", prefix:"apache", reference:"1.3.9-14")) flag++;
if (deb_check(release:"2.2", prefix:"apache-common", reference:"1.3.9-14")) flag++;
if (deb_check(release:"2.2", prefix:"apache-dev", reference:"1.3.9-14")) flag++;
if (deb_check(release:"2.2", prefix:"apache-doc", reference:"1.3.9-14")) flag++;
if (deb_check(release:"2.2", prefix:"apache-ssl", reference:"1.3.9.13-3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
