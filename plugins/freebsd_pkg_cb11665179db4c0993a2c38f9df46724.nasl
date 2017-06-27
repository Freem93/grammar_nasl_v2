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
  script_id(94494);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/21 14:22:36 $");

  script_cve_id("CVE-2016-9013", "CVE-2016-9014");

  script_name(english:"FreeBSD : django -- multiple vulnerabilities (cb116651-79db-4c09-93a2-c38f9df46724)");
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

Today the Django team released Django 1.10.3, Django 1.9.11, and
1.8.16. These releases addresses two security issues detailed below.
We encourage all users of Django to upgrade as soon as possible.

- User with hard-coded password created when running tests on Oracle

- DNS rebinding vulnerability when DEBUG=True"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.djangoproject.com/weblog/2016/nov/01/security-releases/"
  );
  # http://www.freebsd.org/ports/portaudit/cb116651-79db-4c09-93a2-c38f9df46724.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e3d1970"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-django110");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-django18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-django19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py33-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py33-django110");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py33-django18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py33-django19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py34-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py34-django110");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py34-django18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py34-django19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py35-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py35-django110");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py35-django18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py35-django19");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"py27-django<1.8.16")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py33-django<1.8.16")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py34-django<1.8.16")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py35-django<1.8.16")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py27-django18<1.8.16")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py33-django18<1.8.16")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py34-django18<1.8.16")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py35-django18<1.8.16")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py27-django19<1.9.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py33-django19<1.9.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py34-django19<1.9.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py35-django19<1.9.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py27-django110<1.10.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py33-django110<1.10.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py34-django110<1.10.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py35-django110<1.10.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
