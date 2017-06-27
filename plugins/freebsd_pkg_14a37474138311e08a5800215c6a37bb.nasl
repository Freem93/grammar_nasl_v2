#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2016 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
# 
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

include("compat.inc");

if (description)
{
  script_id(51393);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/09 15:44:46 $");

  script_cve_id("CVE-2010-4534", "CVE-2010-4535");
  script_bugtraq_id(45562, 45563);
  script_xref(name:"Secunia", value:"42715");

  script_name(english:"FreeBSD : django -- multiple vulnerabilities (14a37474-1383-11e0-8a58-00215c6a37bb)");
  script_summary(english:"Checks for updated packages in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote FreeBSD host is missing one or more security-related
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Django project reports :

Today the Django team is issuing multiple releases -- Django 1.2.4,
Django 1.1.3 and Django 1.3 beta 1 -- to remedy two security issues
reported to us. All users of affected versions of Django are urged to
upgrade immediately. Information leakage in Django administrative
interface The Django administrative interface, django.contrib.admin
supports filtering of displayed lists of objects by fields on the
corresponding models, including across database-level relationships.
This is implemented by passing lookup arguments in the querystring
portion of the URL, and options on the ModelAdmin class allow
developers to specify particular fields or relationships which will
generate automatic links for filtering. Denial-of-service attack in
password-reset mechanism Django's bundled authentication framework,
django.contrib.auth, offers views which allow users to reset a
forgotten password. The reset mechanism involves generating a one-time
token composed from the user's ID, the timestamp of the reset request
converted to a base36 integer, and a hash derived from the user's
current password hash (which will change once the reset is complete,
thus invalidating the token)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=665373"
  );
  # http://www.freebsd.org/ports/portaudit/14a37474-1383-11e0-8a58-00215c6a37bb.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6f288fad"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py23-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py23-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py24-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py24-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py25-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py25-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py26-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py26-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py30-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py30-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py31-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py31-django-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"py23-django>1.2<1.2.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py23-django>1.1<1.1.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py24-django>1.2<1.2.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py24-django>1.1<1.1.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py25-django>1.2<1.2.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py25-django>1.1<1.1.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py26-django>1.2<1.2.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py26-django>1.1<1.1.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py27-django>1.2<1.2.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py27-django>1.1<1.1.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py30-django>1.2<1.2.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py30-django>1.1<1.1.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py31-django>1.2<1.2.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py31-django>1.1<1.1.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py23-django-devel<15032,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py24-django-devel<15032,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py25-django-devel<15032,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py26-django-devel<15032,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py27-django-devel<15032,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py30-django-devel<15032,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py31-django-devel<15032,1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
