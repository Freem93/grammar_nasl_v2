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
  script_id(92739);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/10/19 14:02:54 $");

  script_cve_id("CVE-2016-6185");

  script_name(english:"FreeBSD : p5-XSLoader -- local arbitrary code execution (3e08047f-5a6c-11e6-a6c3-14dae9d210b8)");
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
"Jakub Wilk reports :

XSLoader tries to load code from a subdirectory in the cwd when called
inside a string eval"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=829578"
  );
  # http://www.freebsd.org/ports/portaudit/3e08047f-5a6c-11e6-a6c3-14dae9d210b8.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?28199099"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:p5-XSLoader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:perl5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:perl5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:perl5.18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:perl5.20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:perl5.22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:perl5.24");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/05");
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

if (pkg_test(save_report:TRUE, pkg:"p5-XSLoader<0.22")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5<5.18.4_24")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5>=5.20<5.20.3_15")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5>=5.21<5.22.3.r2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5>=5.23<5.24.1.r2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5>=5.25<5.25.2.87")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5.18<5.18.4_24")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5.18>=5.20<5.20.3_15")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5.18>=5.21<5.22.3.r2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5.18>=5.23<5.24.1.r2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5.18>=5.25<5.25.2.87")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5.20<5.18.4_24")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5.20>=5.20<5.20.3_15")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5.20>=5.21<5.22.3.r2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5.20>=5.23<5.24.1.r2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5.20>=5.25<5.25.2.87")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5.22<5.18.4_24")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5.22>=5.20<5.20.3_15")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5.22>=5.21<5.22.3.r2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5.22>=5.23<5.24.1.r2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5.22>=5.25<5.25.2.87")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5.24<5.18.4_24")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5.24>=5.20<5.20.3_15")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5.24>=5.21<5.22.3.r2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5.24>=5.23<5.24.1.r2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5.24>=5.25<5.25.2.87")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5-devel<5.18.4_24")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5-devel>=5.20<5.20.3_15")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5-devel>=5.21<5.22.3.r2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5-devel>=5.23<5.24.1.r2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl5-devel>=5.25<5.25.2.87")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl>=0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
