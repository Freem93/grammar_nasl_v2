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
  script_id(21504);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/05 16:01:15 $");

  script_cve_id("CVE-2005-3912", "CVE-2005-3962");
  script_bugtraq_id(15629);

  script_name(english:"FreeBSD : perl, webmin, usermin -- perl format string integer wrap vulnerability (bb33981a-7ac6-11da-bf72-00123f589060)");
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
"The Perl Development page reports :

Dyad Security recently released a security advisory explaining how in
certain cases, a carefully crafted format string passed to sprintf can
cause a buffer overflow. This buffer overflow can then be used by an
attacker to execute code on the machine. This was discovered in the
context of a design problem with the Webmin administration package
that allowed a malicious user to pass unchecked data into sprintf."
  );
  # http://dev.perl.org/perl5/news/2005/perl_patches_fix_sprintf_buffer.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6f9c3013"
  );
  # http://www.dyadsecurity.com/perl-0002.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a844180b"
  );
  # http://www.dyadsecurity.com/webmin-0001.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e5db4928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.webmin.com/security.html"
  );
  # http://www.freebsd.org/ports/portaudit/bb33981a-7ac6-11da-bf72-00123f589060.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5aabe66f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:usermin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:webmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"perl>=5.6.0<5.6.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"perl>=5.8.0<5.8.7_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"webmin<1.250")) flag++;
if (pkg_test(save_report:TRUE, pkg:"usermin<1.180")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
