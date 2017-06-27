#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2332. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56671);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:31:56 $");

  script_cve_id("CVE-2011-4136", "CVE-2011-4137", "CVE-2011-4138", "CVE-2011-4139", "CVE-2011-4140");
  script_bugtraq_id(49573);
  script_osvdb_id(75398, 75399, 75400, 76810, 76811);
  script_xref(name:"DSA", value:"2332");

  script_name(english:"Debian DSA-2332-1 : python-django - several issues");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Paul McMillan, Mozilla and the Django core team discovered several
vulnerabilities in Django, a Python web framework :

  - CVE-2011-4136
    When using memory-based sessions and caching, Django
    sessions are stored directly in the root namespace of
    the cache. When user data is stored in the same cache, a
    remote user may take over a session.

  - CVE-2011-4137, CVE-2011-4138
    Django's field type URLfield by default checks supplied
    URL's by issuing a request to it, which doesn't time
    out. A Denial of Service is possible by supplying
    specially prepared URL's that keep the connection open
    indefinately or fill the Django's server memory.

  - CVE-2011-4139
    Django used X-Forwarded-Host headers to construct full
    URL's. This header may not contain trusted input and
    could be used to poison the cache.

  - CVE-2011-4140
    The CSRF protection mechanism in Django does not
    properly handle web-server configurations supporting
    arbitrary HTTP Host headers, which allows remote
    attackers to trigger unauthenticated forged requests."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=641405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4136"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4137"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4139"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4140"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/python-django"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2332"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the python-django packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.0.2-1+lenny3.

For the stable distribution (squeeze), this problem has been fixed in
version 1.2.3-3+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-django");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"python-django", reference:"1.0.2-1+lenny3")) flag++;
if (deb_check(release:"6.0", prefix:"python-django", reference:"1.2.3-3+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"python-django-doc", reference:"1.2.3-3+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
