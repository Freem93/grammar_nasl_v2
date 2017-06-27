#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2014. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45056);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/05/03 11:20:11 $");

  script_cve_id("CVE-2009-4762", "CVE-2010-0668", "CVE-2010-0669", "CVE-2010-0717");
  script_bugtraq_id(38023);
  script_osvdb_id(54967);
  script_xref(name:"DSA", value:"2014");

  script_name(english:"Debian DSA-2014-1 : moin - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in moin, a python clone
of WikiWiki. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2010-0668
    Multiple security issues in MoinMoin related to
    configurations that have a non-empty superuser list, the
    xmlrpc action enabled, the SyncPages action enabled, or
    OpenID configured.

  - CVE-2010-0669
    MoinMoin does not properly sanitize user profiles.

  - CVE-2010-0717
    The default configuration of
    cfg.packagepages_actions_excluded in MoinMoin does not
    prevent unsafe package actions.

In addition, this update fixes an error when processing hierarchical
ACLs, which can be exploited to access restricted sub-pages."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=569975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2014"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the moin package.

For the stable distribution (lenny), these problems have been fixed in
version 1.7.1-3+lenny3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:moin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"python-moinmoin", reference:"1.7.1-3+lenny3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
