#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-65-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(82210);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/05 14:49:55 $");

  script_cve_id("CVE-2014-0480", "CVE-2014-0481", "CVE-2014-0482", "CVE-2014-0483");
  script_bugtraq_id(69423, 69425, 69429, 69430);
  script_osvdb_id(110378, 110379, 110385, 110386);

  script_name(english:"Debian DLA-65-1 : python-django security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update address an issue with reverse() generating external URLs;
a denial of service involving file uploads; a potential session
hijacking issue in the remote-user middleware; and a data leak in the
administrative interface.

http://www.freexian.com/services/debian-lts.html

CVE-2014-0480

Django includes the helper function django.core.urlresolvers.reverse,
typically used to generate a URL from a reference to a view function
or URL pattern name. However, when presented with input beginning with
two forward-slash characters (//), reverse() could generate
scheme-relative URLs to other hosts, allowing an attacker who is aware
of unsafe use of reverse() (i.e., in a situation where an end user can
control the target of a redirect, to take a common example) to
generate links to sites of their choice, enabling phishing and other
attacks.

To remedy this, URL reversing now ensures that no URL starts
with two slashes (//), replacing the second slash with its
URL encoded counterpart (%2F). This approach ensures that
semantics stay the same, while making the URL relative to
the domain and not to the scheme.

CVE-2014-0481

In the default configuration, when Django's file upload handling
system is presented with a file that would have the same on-disk path
and name as an existing file, it attempts to generate a new unique
filename by appending an underscore and an integer to the end of the
(as stored on disk) filename, incrementing the integer (i.e., _1, _2,
etc.) until it has generated a name which does not conflict with any
existing file.

An attacker with knowledge of this can exploit the
sequential behavior of filename generation by uploading many
tiny files which all share a filename; Django will, in
processing them, generate ever-increasing numbers of
os.stat() calls as it attempts to generate a unique
filename. As a result, even a relatively small number of
such uploads can significantly degrade performance.

To remedy this, Django's file-upload system will no longer
use sequential integer names to avoid filename conflicts on
disk; instead, a short random alphanumeric string will be
appended, removing the ability to reliably generate many
repeatedly-conflicting filenames.

CVE-2014-0482

Django provides a middleware --
django.contrib.auth.middleware.RemoteUserMiddleware -- and an
authentication backend,
django.contrib.auth.backends.RemoteUserBackend, which use the
REMOTE_USER header for authentication purposes.

In some circumstances, use of this middleware and backend
could result in one user receiving another user's session,
if a change to the REMOTE_USER header occurred without
corresponding logout/login actions.

To remedy this, the middleware will now ensure that a change
to REMOTE_USER without an explicit logout will force a
logout and subsequent login prior to accepting the new
REMOTE_USER.

CVE-2014-0483

Django's administrative interface, django.contrib.admin, offers a
feature whereby related objects can be displayed for selection in a
popup window. The mechanism for this relies on placing values in the
URL and querystring which specify the related model to display and the
field through which the relationship is implemented. This mechanism
does perform permission checks at the level of the model class as a
whole.

This mechanism did not, however, verify that the specified
field actually represents a relationship between models.
Thus a user with access to the admin interface, and with
sufficient knowledge of model structure and the appropriate
URLs, could construct popup views which would display the
values of non-relationship fields, including fields the
application developer had not intended to expose in such a
fashion.

To remedy this, the admin interface will now, in addition to
its normal permission checks, verify that the specified
field does indeed represent a relationship, to a model
registered with the admin, and will raise an exception if
either condition is not true.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2014/09/msg00022.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/python-django"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected python-django, and python-django-doc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-django-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
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
if (deb_check(release:"6.0", prefix:"python-django", reference:"1.2.3-3+squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"python-django-doc", reference:"1.2.3-3+squeeze11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
