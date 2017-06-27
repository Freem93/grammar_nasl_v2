#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1362. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25962);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2007-2841", "CVE-2007-3946", "CVE-2007-3947", "CVE-2007-3948", "CVE-2007-3949", "CVE-2007-3950", "CVE-2007-4727");
  script_osvdb_id(38308, 38309, 38310, 38311, 38312, 38313, 38314, 38315, 38316, 38317, 38318);
  script_xref(name:"DSA", value:"1362");

  script_name(english:"Debian DSA-1362-2 : lighttpd - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in lighttpd, a fast webserver
with minimal memory footprint, which could allow the execution of
arbitrary code via the overflow of CGI variables when mod_fcgi was
enabled. The Common Vulnerabilities and Exposures project identifies
the following problems :

  - CVE-2007-3946
    The use of mod_auth could leave to a denial of service
    attack crashing the webserver.

  - CVE-2007-3947
    The improper handling of repeated HTTP headers could
    cause a denial of service attack crashing the webserver.

  - CVE-2007-3949
    A bug in mod_access potentially allows remote users to
    bypass access restrictions via trailing slash
    characters.

  - CVE-2007-3950
    On 32-bit platforms users may be able to create denial
    of service attacks, crashing the webserver, via
    mod_webdav, mod_fastcgi, or mod_scgi."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=434888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3946"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3949"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1362"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the lighttpd package.

For the stable distribution (etch), these problems have been fixed in
version 1.4.13-4etch4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"lighttpd", reference:"1.4.13-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-doc", reference:"1.4.13-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-mod-cml", reference:"1.4.13-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-mod-magnet", reference:"1.4.13-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-mod-mysql-vhost", reference:"1.4.13-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-mod-trigger-b4-dl", reference:"1.4.13-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-mod-webdav", reference:"1.4.13-4etch4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
