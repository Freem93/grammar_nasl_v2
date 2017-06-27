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
  script_id(83909);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/06/04 13:39:49 $");

  script_cve_id("CVE-2015-3982");

  script_name(english:"FreeBSD : django -- Fixed session flushing in the cached_db backend (48504af7-07ad-11e5-879c-00e0814cab4e)");
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
"The Django project reports :

A change to session.flush() in the cached_db session backend in Django
1.8 mistakenly sets the session key to an empty string rather than
None. An empty string is treated as a valid session key and the
session cookie is set accordingly. Any users with an empty string in
their session cookie will use the same session store. session.flush()
is called by django.contrib.auth.logout() and, more seriously, by
django.contrib.auth.login() when a user switches accounts. If a user
is logged in and logs in again to a different account (without logging
out) the session is flushed to avoid reuse. After the session is
flushed (and its session key becomes '') the account details are set
on the session and the session is saved. Any users with an empty
string in their session cookie will now be logged into that account.

Thanks to Sam Cooke for reporting the issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.djangoproject.com/weblog/2015/may/20/security-release/"
  );
  # http://www.freebsd.org/ports/portaudit/48504af7-07ad-11e5-879c-00e0814cab4e.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?86e3e8a7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py32-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py32-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py33-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py33-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py34-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py34-django-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/01");
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

if (pkg_test(save_report:TRUE, pkg:"py27-django>=1.8<1.8.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py32-django>=1.8<1.8.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py33-django>=1.8<1.8.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py34-django>=1.8<1.8.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py27-django-devel<20150531,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py32-django-devel<20150531,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py33-django-devel<20150531,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py34-django-devel<20150531,1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
