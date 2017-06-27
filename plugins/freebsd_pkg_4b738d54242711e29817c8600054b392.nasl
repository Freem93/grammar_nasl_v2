#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2013 Jacques Vidrine and contributors
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
  script_id(62793);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/07/25 10:47:51 $");

  script_cve_id("CVE-2012-4730", "CVE-2012-4731", "CVE-2012-4732", "CVE-2012-4734", "CVE-2012-4884", "CVE-2012-6578", "CVE-2012-6579", "CVE-2012-6580", "CVE-2012-6581");

  script_name(english:"FreeBSD : RT -- Multiple Vulnerabilities (4b738d54-2427-11e2-9817-c8600054b392)");
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
"BestPractical report :

All versions of RT are vulnerable to an email header injection attack.
Users with ModifySelf or AdminUser can cause RT to add arbitrary
headers or content to outgoing mail. Depending on the scrips that are
configured, this may be be leveraged for information leakage or
phishing.

RT 4.0.0 and above and RTFM 2.0.0 and above contain a vulnerability
due to lack of proper rights checking, allowing any privileged user to
create Articles in any class.

All versions of RT with cross-site-request forgery (CSRF) protection
(RT 3.8.12 and above, RT 4.0.6 and above, and any instances running
the security patches released 2012-05-22) contain a vulnerability
which incorrectly allows though CSRF requests which toggle ticket
bookmarks.

All versions of RT are vulnerable to a confused deputy attack on the
user. While not strictly a CSRF attack, users who are not logged in
who are tricked into following a malicious link may, after supplying
their credentials, be subject to an attack which leverages their
credentials to modify arbitrary state. While users who were logged in
would have observed the CSRF protection page, users who were not
logged in receive no such warning due to the intervening login
process. RT has been extended to notify users of pending actions
during the login process.

RT 3.8.0 and above are susceptible to a number of vulnerabilities
concerning improper signing or encryption of messages using GnuPG; if
GnuPG is not enabled, none of the following affect you."
  );
  # http://blog.bestpractical.com/2012/10/security-vulnerabilities-in-rt.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2181f5d2"
  );
  # http://www.freebsd.org/ports/portaudit/4b738d54-2427-11e2-9817-c8600054b392.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b31f7abd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rt38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rt40");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"rt40>=4.0<4.0.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"rt38<3.8.15")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
