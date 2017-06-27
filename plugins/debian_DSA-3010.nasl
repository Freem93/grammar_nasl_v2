#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3010. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77344);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/04/28 18:23:48 $");

  script_cve_id("CVE-2014-0480", "CVE-2014-0481", "CVE-2014-0482", "CVE-2014-0483");
  script_osvdb_id(110378, 110379, 110385, 110386);
  script_xref(name:"DSA", value:"3010");

  script_name(english:"Debian DSA-3010-1 : python-django - security update");
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

  - CVE-2014-0480
    Florian Apolloner discovered that in certain situations,
    URL reversing could generate scheme-relative URLs which
    could unexpectedly redirect a user to a different host,
    leading to phishing attacks.

  - CVE-2014-0481
    David Wilson reported a file upload denial of service
    vulnerability. Django's file upload handling in its
    default configuration may degrade to producing a huge
    number of `os.stat()` system calls when a duplicate
    filename is uploaded. A remote attacker with the ability
    to upload files can cause poor performance in the upload
    handler, eventually causing it to become very slow.

  - CVE-2014-0482
    David Greisen discovered that under some circumstances,
    the use of the RemoteUserMiddleware middleware and the
    RemoteUserBackend authentication backend could result in
    one user receiving another user's session, if a change
    to the REMOTE_USER header occurred without corresponding
    logout/login actions.

  - CVE-2014-0483
    Collin Anderson discovered that it is possible to reveal
    any field's data by modifying the 'popup' and 'to_field'
    parameters of the query string on an admin change form
    page. A user with access to the admin interface, and
    with sufficient knowledge of model structure and the
    appropriate URLs, could construct popup views which
    would display the values of non-relationship fields,
    including fields the application developer had not
    intended to expose in such a fashion."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0481"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0482"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/python-django"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-3010"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the python-django packages.

For the stable distribution (wheezy), these problems have been fixed
in version 1.4.5-1+deb7u8."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-django");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"python-django", reference:"1.4.5-1+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"python-django-doc", reference:"1.4.5-1+deb7u8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
