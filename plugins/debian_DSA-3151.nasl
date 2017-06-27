#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3151. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81131);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/05 16:01:11 $");

  script_cve_id("CVE-2015-0219", "CVE-2015-0220", "CVE-2015-0221");
  script_bugtraq_id(72078, 72079, 72081);
  script_osvdb_id(117065, 117066, 117067);
  script_xref(name:"DSA", value:"3151");

  script_name(english:"Debian DSA-3151-1 : python-django - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Django, a high-level Python
web development framework. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2015-0219
    Jedediah Smith reported that the WSGI environ in Django
    does not distinguish between headers containing dashes
    and headers containing underscores. A remote attacker
    could use this flaw to spoof WSGI headers.

  - CVE-2015-0220
    Mikko Ohtamaa discovered that the
    django.util.http.is_safe_url() function in Django does
    not properly handle leading whitespaces in user-supplied
    redirect URLs. A remote attacker could potentially use
    this flaw to perform a cross-site scripting attack.

  - CVE-2015-0221
    Alex Gaynor reported a flaw in the way Django handles
    reading files in the django.views.static.serve() view. A
    remote attacker could possibly use this flaw to mount a
    denial of service via resource consumption."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=775375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-0219"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-0220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-0221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/python-django"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3151"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the python-django packages.

For the stable distribution (wheezy), these problems have been fixed
in version 1.4.5-1+deb7u9.

For the upcoming stable distribution (jessie), these problems have
been fixed in version 1.7.1-1.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-django");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"python-django", reference:"1.4.5-1+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"python-django-doc", reference:"1.4.5-1+deb7u9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
