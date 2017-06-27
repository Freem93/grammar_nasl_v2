#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2014 Jacques Vidrine and contributors
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
  script_id(73676);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/05/01 10:41:21 $");

  script_cve_id("CVE-2014-0472", "CVE-2014-0473", "CVE-2014-0474");

  script_name(english:"FreeBSD : django -- multiple vulnerabilities (59e72db2-cae6-11e3-8420-00e0814cab4e)");
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

These releases address an unexpected code-execution issue, a caching
issue which can expose CSRF tokens and a MySQL typecasting issue.
While these issues present limited risk and may not affect all Django
users, we encourage all users to evaluate their own risk and upgrade
as soon as possible."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.djangoproject.com/weblog/2014/apr/21/security/"
  );
  # http://www.freebsd.org/ports/portaudit/59e72db2-cae6-11e3-8420-00e0814cab4e.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dd18d58d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py26-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py26-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py26-django14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py26-django15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-django14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-django15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py31-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py31-django14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py31-django15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py32-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py32-django14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py32-django15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py33-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py33-django14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py33-django15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py34-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py34-django14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py34-django15");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"py26-django>=1.6<1.6.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py27-django>=1.6<1.6.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py31-django>=1.6<1.6.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py32-django>=1.6<1.6.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py33-django>=1.6<1.6.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py34-django>=1.6<1.6.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py26-django15>=1.5<1.5.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py27-django15>=1.5<1.5.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py31-django15>=1.5<1.5.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py32-django15>=1.5<1.5.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py33-django15>=1.5<1.5.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py34-django15>=1.5<1.5.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py26-django14>=1.4<1.4.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py27-django14>=1.4<1.4.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py31-django14>=1.4<1.4.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py32-django14>=1.4<1.4.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py33-django14>=1.4<1.4.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py34-django14>=1.4<1.4.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py26-django-devel<20140423,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py27-django-devel<20140423,1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
