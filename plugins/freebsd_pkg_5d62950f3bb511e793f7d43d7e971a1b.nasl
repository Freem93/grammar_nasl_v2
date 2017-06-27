#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2017 Jacques Vidrine and contributors
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
  script_id(100284);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/19 13:47:30 $");

  script_cve_id("CVE-2017-0882");

  script_name(english:"FreeBSD : gitlab -- Various security issues (5d62950f-3bb5-11e7-93f7-d43d7e971a1b)");
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
"GitLab reports : Information Disclosure in Issue and Merge Request
Trackers During an internal code review a critical vulnerability in
the GitLab Issue and Merge Request trackers was discovered. This
vulnerability could allow a user with access to assign ownership of an
issue or merge request to another user to disclose that user's private
token, email token, email address, and encrypted OTP secret.
Reporter-level access to a GitLab project is required to exploit this
flaw. SSRF when importing a project from a Repo by URL GitLab
instances that have enabled project imports using 'Repo by URL' were
vulnerable to Server-Side Request Forgery attacks. By specifying a
project import URL of localhost an attacker could target services that
are bound to the local interface of the server. These services often
do not require authentication. Depending on the service an attacker
might be able craft an attack using the project import request URL.
Links in Environments tab vulnerable to tabnabbing edio via HackerOne
reported that user-configured Environment links include target=_blank
but do not also include rel: noopener noreferrer. Anyone clicking on
these links may therefore be subjected to tabnabbing attacks where a
link back to the requesting page is maintained and can be manipulated
by the target server. Accounts with email set to 'Do not show on
profile' have addresses exposed in public atom feed Several GitLab
users reported that even with 'Do not show on profile' configured for
their email addresses those addresses were still being leaked in Atom
feeds if they commented on a public project."
  );
  # https://about.gitlab.com/2017/03/20/gitlab-8-dot-17-dot-4-security-release/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2b29199"
  );
  # http://www.freebsd.org/ports/portaudit/5d62950f-3bb5-11e7-93f7-d43d7e971a1b.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e865d668"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gitlab");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"gitlab>=8.7.0<=8.15.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gitlab>=8.16.0<=8.16.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gitlab>=8.17.0<=8.17.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
