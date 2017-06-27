#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2015 Jacques Vidrine and contributors
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
  script_id(85522);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/08/26 13:32:36 $");

  script_cve_id("CVE-2015-5963", "CVE-2015-5964");

  script_name(english:"FreeBSD : django -- multiple vulnerabilities (b0e54dc1-45d2-11e5-adde-14dae9d210b8)");
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
"Tim Graham reports :

Denial-of-service possibility in logout() view by filling session
store

Previously, a session could be created when anonymously accessing the
django.contrib.auth.views.logout view (provided it wasn't decorated
with django.contrib.auth.decorators.login_required as done in the
admin). This could allow an attacker to easily create many new session
records by sending repeated requests, potentially filling up the
session store or causing other users' session records to be evicted.

The django.contrib.sessions.middleware.SessionMiddleware has been
modified to no longer create empty session records.

This portion of the fix has been assigned CVE-2015-5963.

Additionally, on the 1.4 and 1.7 series only, the
contrib.sessions.backends.base.SessionBase.flush() and
cache_db.SessionStore.flush() methods have been modified to avoid
creating a new empty session. Maintainers of third-party session
backends should check if the same vulnerability is present in their
backend and correct it if so.

This portion of the fix has been assigned CVE-2015-5964. Anyone
reporting a similar vulnerability in a third-party session backend
should not use this CVE ID.

Thanks Lin Hua Cheng for reporting the issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.djangoproject.com/weblog/2015/aug/18/security-releases/"
  );
  # http://www.freebsd.org/ports/portaudit/b0e54dc1-45d2-11e5-adde-14dae9d210b8.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d75f4a83"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-django14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-django17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py32-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py32-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py32-django14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py32-django17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py33-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py33-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py33-django14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py33-django17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py34-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py34-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py34-django14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py34-django17");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"py27-django<1.8.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py32-django<1.8.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py33-django<1.8.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py34-django<1.8.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py27-django17<1.7.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py32-django17<1.7.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py33-django17<1.7.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py34-django17<1.7.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py27-django14<1.4.22")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py32-django14<1.4.22")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py33-django14<1.4.22")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py34-django14<1.4.22")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py27-django-devel<=20150709,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py32-django-devel<=20150709,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py33-django-devel<=20150709,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py34-django-devel<=20150709,1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
