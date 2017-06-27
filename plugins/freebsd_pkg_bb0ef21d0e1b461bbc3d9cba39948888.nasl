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
  script_id(88532);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/12/08 20:42:12 $");

  script_cve_id("CVE-2015-7576", "CVE-2015-7577", "CVE-2015-7581", "CVE-2016-0751", "CVE-2016-0752", "CVE-2016-0753");

  script_name(english:"FreeBSD : rails -- multiple vulnerabilities (bb0ef21d-0e1b-461b-bc3d-9cba39948888)");
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

Rails 5.0.0.beta1.1, 4.2.5.1, 4.1.14.1, and 3.2.22.1 have been
released! These contain important security fixes, and it is
recommended that users upgrade as soon as possible."
  );
  # https://groups.google.com/d/msg/rubyonrails-security/ANv0HDHEC3k/mt7wNGxbFQAJ
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3186c1e2"
  );
  # https://groups.google.com/d/msg/rubyonrails-security/cawsWcQ6c8g/tegZtYdbFQAJ
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42de9ca4"
  );
  # https://groups.google.com/d/msg/rubyonrails-security/dthJ5wL69JE/YzPnFelbFQAJ
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?be388111"
  );
  # https://groups.google.com/d/msg/rubyonrails-security/9oLY_FCzvoc/w9oI9XxbFQAJ
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2fcd6bd9"
  );
  # https://groups.google.com/d/msg/rubyonrails-security/335P1DcLG00/OfB9_LhbFQAJ
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c9373e0"
  );
  # https://groups.google.com/d/msg/rubyonrails-security/6jQVC1geukQ/8oYETcxbFQAJ
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2dafa51e"
  );
  # http://weblog.rubyonrails.org/2016/1/25/Rails-5-0-0-beta1-1-4-2-5-1-4-1-14-1-3-2-22-1-and-rails-html-sanitizer-1-0-3-have-been-released/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52f0baa2"
  );
  # http://www.freebsd.org/ports/portaudit/bb0ef21d-0e1b-461b-bc3d-9cba39948888.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e389abc4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ruby on Rails Dynamic Render File Upload Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rubygem-actionpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rubygem-actionpack4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rubygem-actionview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rubygem-activemodel4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rubygem-activerecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rubygem-activerecord4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rubygem-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rubygem-rails-html-sanitizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rubygem-rails4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/03");
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

if (pkg_test(save_report:TRUE, pkg:"rubygem-actionpack<3.2.22.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"rubygem-actionpack4<4.2.5.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"rubygem-actionview<4.2.5.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"rubygem-activemodel4<4.2.5.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"rubygem-activerecord<3.2.22.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"rubygem-activerecord4<4.2.5.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"rubygem-rails<3.2.22.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"rubygem-rails-html-sanitizer<1.0.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"rubygem-rails4<4.2.5.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
