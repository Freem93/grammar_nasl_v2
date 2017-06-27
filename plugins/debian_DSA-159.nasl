#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-159. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14996);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/05/17 23:45:46 $");

  script_cve_id("CVE-2002-1119");
  script_bugtraq_id(5581);
  script_xref(name:"DSA", value:"159");

  script_name(english:"Debian DSA-159-1 : python - insecure temporary files");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Zack Weinberg discovered an insecure use of a temporary file in
os._execvpe from os.py. It uses a predictable name which could lead
execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-159"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Python packages immediately.

This problem has been fixed in several versions of Python: For the
current stable distribution (woody) it has been fixed in version
1.5.2-23.1 of Python 1.5, in version 2.1.3-3.1 of Python 2.1 and in
version 2.2.1-4.1 of Python 2.2. For the old stable distribution
(potato) this has been fixed in version 1.5.2-10potato12 for Python
1.5. For the unstable distribution (sid) this has been fixed in
version 1.5.2-24 of Python 1.5, in version 2.1.3-6a of Python 2.1 and
in version 2.2.1-8 of Python 2.2. Python 2.3 is not affected by this
problem."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
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
if (deb_check(release:"2.2", prefix:"idle", reference:"1.5.2-10potato13")) flag++;
if (deb_check(release:"2.2", prefix:"python-base", reference:"1.5.2-10potato13")) flag++;
if (deb_check(release:"2.2", prefix:"python-dev", reference:"1.5.2-10potato13")) flag++;
if (deb_check(release:"2.2", prefix:"python-elisp", reference:"1.5.2-10potato13")) flag++;
if (deb_check(release:"2.2", prefix:"python-examples", reference:"1.5.2-10potato13")) flag++;
if (deb_check(release:"2.2", prefix:"python-gdbm", reference:"1.5.2-10potato13")) flag++;
if (deb_check(release:"2.2", prefix:"python-mpz", reference:"1.5.2-10potato13")) flag++;
if (deb_check(release:"2.2", prefix:"python-regrtest", reference:"1.5.2-10potato13")) flag++;
if (deb_check(release:"2.2", prefix:"python-tk", reference:"1.5.2-10potato13")) flag++;
if (deb_check(release:"2.2", prefix:"python-zlib", reference:"1.5.2-10potato13")) flag++;
if (deb_check(release:"3.0", prefix:"idle", reference:"2.1.3-3.2")) flag++;
if (deb_check(release:"3.0", prefix:"idle-python1.5", reference:"1.5.2-23.2")) flag++;
if (deb_check(release:"3.0", prefix:"idle-python2.1", reference:"2.1.3-3.2")) flag++;
if (deb_check(release:"3.0", prefix:"idle-python2.2", reference:"2.2.1-4.2")) flag++;
if (deb_check(release:"3.0", prefix:"python", reference:"2.1.3-3.2")) flag++;
if (deb_check(release:"3.0", prefix:"python-dev", reference:"2.1.3-3.2")) flag++;
if (deb_check(release:"3.0", prefix:"python-doc", reference:"2.1.3-3.2")) flag++;
if (deb_check(release:"3.0", prefix:"python-elisp", reference:"2.1.3-3.2")) flag++;
if (deb_check(release:"3.0", prefix:"python-examples", reference:"2.1.3-3.2")) flag++;
if (deb_check(release:"3.0", prefix:"python-gdbm", reference:"2.1.3-3.2")) flag++;
if (deb_check(release:"3.0", prefix:"python-mpz", reference:"2.1.3-3.2")) flag++;
if (deb_check(release:"3.0", prefix:"python-tk", reference:"2.1.3-3.2")) flag++;
if (deb_check(release:"3.0", prefix:"python-xmlbase", reference:"2.1.3-3.2")) flag++;
if (deb_check(release:"3.0", prefix:"python1.5", reference:"1.5.2-23.2")) flag++;
if (deb_check(release:"3.0", prefix:"python1.5-dev", reference:"1.5.2-23.2")) flag++;
if (deb_check(release:"3.0", prefix:"python1.5-examples", reference:"1.5.2-23.2")) flag++;
if (deb_check(release:"3.0", prefix:"python1.5-gdbm", reference:"1.5.2-23.2")) flag++;
if (deb_check(release:"3.0", prefix:"python1.5-mpz", reference:"1.5.2-23.2")) flag++;
if (deb_check(release:"3.0", prefix:"python1.5-tk", reference:"1.5.2-23.2")) flag++;
if (deb_check(release:"3.0", prefix:"python2.1", reference:"2.1.3-3.2")) flag++;
if (deb_check(release:"3.0", prefix:"python2.1-dev", reference:"2.1.3-3.2")) flag++;
if (deb_check(release:"3.0", prefix:"python2.1-doc", reference:"2.1.3-3.2")) flag++;
if (deb_check(release:"3.0", prefix:"python2.1-elisp", reference:"2.1.3-3.2")) flag++;
if (deb_check(release:"3.0", prefix:"python2.1-examples", reference:"2.1.3-3.2")) flag++;
if (deb_check(release:"3.0", prefix:"python2.1-gdbm", reference:"2.1.3-3.2")) flag++;
if (deb_check(release:"3.0", prefix:"python2.1-mpz", reference:"2.1.3-3.2")) flag++;
if (deb_check(release:"3.0", prefix:"python2.1-tk", reference:"2.1.3-3.2")) flag++;
if (deb_check(release:"3.0", prefix:"python2.1-xmlbase", reference:"2.1.3-3.2")) flag++;
if (deb_check(release:"3.0", prefix:"python2.2", reference:"2.2.1-4.2")) flag++;
if (deb_check(release:"3.0", prefix:"python2.2-dev", reference:"2.2.1-4.2")) flag++;
if (deb_check(release:"3.0", prefix:"python2.2-doc", reference:"2.2.1-4.2")) flag++;
if (deb_check(release:"3.0", prefix:"python2.2-elisp", reference:"2.2.1-4.2")) flag++;
if (deb_check(release:"3.0", prefix:"python2.2-examples", reference:"2.2.1-4.2")) flag++;
if (deb_check(release:"3.0", prefix:"python2.2-gdbm", reference:"2.2.1-4.2")) flag++;
if (deb_check(release:"3.0", prefix:"python2.2-mpz", reference:"2.2.1-4.2")) flag++;
if (deb_check(release:"3.0", prefix:"python2.2-tk", reference:"2.2.1-4.2")) flag++;
if (deb_check(release:"3.0", prefix:"python2.2-xmlbase", reference:"2.2.1-4.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
