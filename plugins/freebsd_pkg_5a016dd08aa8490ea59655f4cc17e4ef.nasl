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
  script_id(89708);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/08 20:31:55 $");

  script_cve_id("CVE-2016-2097", "CVE-2016-2098");

  script_name(english:"FreeBSD : rails -- multiple vulnerabilities (5a016dd0-8aa8-490e-a596-55f4cc17e4ef)");
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
"Ruby on Rails blog :

Rails 4.2.5.2, 4.1.14.2, and 3.2.22.2 have been released! These
contain the following important security fixes, and it is recommended
that users upgrade as soon as possible."
  );
  # https://groups.google.com/d/msg/rubyonrails-security/ddY6HgqB2z4/we0RasMZIAAJ
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2f53d93"
  );
  # https://groups.google.com/d/msg/rubyonrails-security/ly-IH-fxr_Q/WLoOhcMZIAAJ
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e779caef"
  );
  # http://weblog.rubyonrails.org/2016/2/29/Rails-4-2-5-2-4-1-14-2-3-2-22-2-have-been-released/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?39fc2a50"
  );
  # http://www.freebsd.org/ports/portaudit/5a016dd0-8aa8-490e-a596-55f4cc17e4ef.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?81d30c3d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ruby on Rails ActionPack Inline ERB Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rubygem-actionpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rubygem-actionpack4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rubygem-actionview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rubygem-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rubygem-rails4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/07");
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

if (pkg_test(save_report:TRUE, pkg:"rubygem-actionpack<3.2.22.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"rubygem-actionpack4<4.2.5.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"rubygem-actionview<4.2.5.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"rubygem-rails<3.2.22.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"rubygem-rails4<4.2.5.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
