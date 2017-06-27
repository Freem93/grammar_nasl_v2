#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-674. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16348);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2014/08/13 14:23:42 $");

  script_cve_id("CVE-2004-1177", "CVE-2005-0202");
  script_osvdb_id(13671);
  script_xref(name:"DSA", value:"674");

  script_name(english:"Debian DSA-674-3 : mailman - XSS, directory traversal");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Due to an incompatibility between Python 1.5 and 2.1 the last mailman
update did not run with Python 1.5 anymore. This problem is corrected
with this update. This advisory only updates the packages updated with
DSA 674-2. The version in unstable is not affected since it is not
supposed to work with Python 1.5 anymore. For completeness below is
the original advisory text :

  Two security related problems have been discovered in mailman,
  web-based GNU mailing list manager. The Common Vulnerabilities and
  Exposures project identifies the following problems :

    - CAN-2004-1177
      Florian Weimer discovered a cross-site scripting
      vulnerability in mailman's automatically generated
      error messages. An attacker could craft a URL
      containing JavaScript (or other content embedded into
      HTML) which triggered a mailman error page that would
      include the malicious code verbatim.

    - CAN-2005-0202

      Several listmasters have noticed unauthorised access
      to archives of private lists and the list
      configuration itself, including the users passwords.
      Administrators are advised to check the webserver
      logfiles for requests that contain '/...../' and the
      path to the archives or configuration. This does only
      seem to affect installations running on web servers
      that do not strip slashes, such as Apache 1.3."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-674"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mailman package.

For the stable distribution (woody) these problems have been fixed in
version 2.0.11-1woody11."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mailman");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"mailman", reference:"2.0.11-1woody11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
