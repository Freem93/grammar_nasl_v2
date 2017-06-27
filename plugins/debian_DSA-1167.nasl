#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1167. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22709);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2014/05/03 11:14:57 $");

  script_cve_id("CVE-2005-3352", "CVE-2006-3918");
  script_osvdb_id(21705, 27487, 27488);
  script_xref(name:"DSA", value:"1167");

  script_name(english:"Debian DSA-1167-1 : apache - missing input sanitising ");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in the Apache, the
worlds most popular webserver, which may lead to the execution of
arbitrary web script. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2005-3352
    A cross-site scripting (XSS) flaw exists in the mod_imap
    component of the Apache server.

  - CVE-2006-3918
    Apache does not sanitize the Expect header from an HTTP
    request when it is reflected back in an error message,
    which might allow cross-site scripting (XSS) style
    attacks."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=381381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=343466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3352"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3918"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1167"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the apache package.

For the stable distribution (sarge) these problems have been fixed in
version 1.3.33-6sarge3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"apache", reference:"1.3.33-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"apache-common", reference:"1.3.33-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"apache-dbg", reference:"1.3.33-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"apache-dev", reference:"1.3.33-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"apache-doc", reference:"1.3.33-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"apache-perl", reference:"1.3.33-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"apache-ssl", reference:"1.3.33-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"apache-utils", reference:"1.3.33-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libapache-mod-perl", reference:"1.29.0.3-6sarge3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
