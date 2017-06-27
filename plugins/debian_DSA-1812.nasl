#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1812. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39333);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/06 20:12:52 $");

  script_cve_id("CVE-2009-0023", "CVE-2009-1955");
  script_osvdb_id(55057, 55059);
  script_xref(name:"DSA", value:"1812");

  script_name(english:"Debian DSA-1812-1 : apr-util - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Apr-util, the Apache Portable Runtime Utility library, is used by
Apache 2.x, Subversion, and other applications. Two denial of service
vulnerabilities have been found in apr-util :

  - 'kcope' discovered a flaw in the handling of internal
    XML entities in the apr_xml_* interface that can be
    exploited to use all available memory. This denial of
    service can be triggered remotely in the Apache mod_dav
    and mod_dav_svn modules. (No CVE id yet)
  - CVE-2009-0023
    Matthew Palmer discovered an underflow flaw in the
    apr_strmatch_precompile function that can be exploited
    to cause a daemon crash. The vulnerability can be
    triggered (1) remotely in mod_dav_svn for Apache if the
    'SVNMasterURI' directive is in use, (2) remotely in
    mod_apreq2 for Apache or other applications using
    libapreq2, or (3) locally in Apache by a crafted
    '.htaccess' file.

Other exploit paths in other applications using apr-util may exist.

If you use Apache, or if you use svnserve in standalone mode, you need
to restart the services after you upgraded the libaprutil1 package.

The oldstable distribution (etch), these problems have been fixed in
version 1.2.7+dfsg-2+etch2."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1812"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the apr-util packages.

For the stable distribution (lenny), these problems have been fixed in
version 1.2.12+dfsg-8+lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apr-util");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libaprutil1", reference:"1.2.7+dfsg-2+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libaprutil1-dbg", reference:"1.2.7+dfsg-2+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libaprutil1-dev", reference:"1.2.7+dfsg-2+etch2")) flag++;
if (deb_check(release:"5.0", prefix:"libaprutil1", reference:"1.2.12+dfsg-8+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libaprutil1-dbg", reference:"1.2.12+dfsg-8+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libaprutil1-dev", reference:"1.2.12+dfsg-8+lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
