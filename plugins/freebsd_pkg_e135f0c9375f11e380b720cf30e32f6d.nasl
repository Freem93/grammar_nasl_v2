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
  script_id(70485);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/05/01 10:41:21 $");

  script_cve_id("CVE-2013-1733", "CVE-2013-1734", "CVE-2013-1742", "CVE-2013-1743");

  script_name(english:"FreeBSD : bugzilla -- multiple vulnerabilities (e135f0c9-375f-11e3-80b7-20cf30e32f6d)");
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
"A Bugzilla Security Advisory reports:Cross-Site Request Forgery When a
user submits changes to a bug right after another user did, a midair
collision page is displayed to inform the user about changes recently
made. This page contains a token which can be used to validate the
changes if the user decides to submit his changes anyway. A regression
in Bugzilla 4.4 caused this token to be recreated if a crafted URL was
given, even when no midair collision page was going to be displayed,
allowing an attacker to bypass the token check and abuse a user to
commit changes on his behalf. Cross-Site Request Forgery When an
attachment is edited, a token is generated to validate changes made by
the user. Using a crafted URL, an attacker could force the token to be
recreated, allowing him to bypass the token check and abuse a user to
commit changes on his behalf. Cross-Site Scripting Some parameters
passed to editflagtypes.cgi were not correctly filtered in the HTML
page, which could lead to XSS. Cross-Site Scripting Due to an
incomplete fix for CVE-2012-4189, some incorrectly filtered field
values in tabular reports could lead to XSS."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=911593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=913904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=924802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=924932"
  );
  # http://www.freebsd.org/ports/portaudit/e135f0c9-375f-11e3-80b7-20cf30e32f6d.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe187254"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bugzilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bugzilla40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bugzilla42");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bugzilla44");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"bugzilla>=4.0.0<4.0.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bugzilla40>=4.0.0<4.0.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bugzilla42>=4.2.0<4.2.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bugzilla44>=4.4<4.4.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
