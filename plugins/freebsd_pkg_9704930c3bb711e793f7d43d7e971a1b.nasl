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

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(100285);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/19 13:47:30 $");

  script_name(english:"FreeBSD : gitlab -- Various security issues (9704930c-3bb7-11e7-93f7-d43d7e971a1b)");
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
"GitLab reports : Cross-Site Scripting (XSS) vulnerability in project
import file names for gitlab_project import types Timo Schmid from
ERNW reported a persistent Cross-Site Scripting vulnerability in the
new project import view for gitlab_project import types. This XSS
vulnerability was caused by the use of Hamlit filters inside HAML
views without manually escaping HTML. Unlike content outside of a
filter, content inside Hamlit filters (:css, :javascript, :preserve,
:plain) is not automatically escaped. Cross-Site Scripting (XSS)
vulnerability in git submodule support Jobert Abma from HackerOne
reported a persitent XSS vulnerability in the GitLab repository files
view that could be exploited by injecting malicious script into a git
submodule. Cross-Site Scripting (XSS) vulnerability in repository 'new
branch' view A GitLab user reported a persistent XSS vulnerability in
the repository new branch view that allowed malicious branch names or
git references to execute arbitrary JavaScript. Cross-Site Scripting
(XSS) vulnerability in mirror errors display While investigating Timo
Schmid's previously reported XSS vulnerability in import filenames
another persistent XSS vulnerability was discovered in the GitLab
Enterprise Edition's (EE) mirror view. This vulnerability was also
caused by the misuse of Hamlit filters. Potential XSS vulnerability in
DropLab An internal code audit disclosed a vulnerability in DropLab's
templating that, while not currently exploitable, could become
exploitable depending on how the templates were used in the future.
Tab Nabbing vulnerabilities in mardown link filter, Asciidoc files,
and other markup files edio via HackerOne reported two tab nabbing
vulnerabilities. The first tab nabbing vulnerability was caused by
improper hostname filtering when identifying user-supplied external
links. GitLab did not properly filter usernames from the URL. An
attacker could construct a specially crafted link including a username
to bypass GitLab's external link filter. This allowed an attacker to
post links in Markdown that did not include the appropriate
'noreferrer noopener' options, allowing tab nabbing attacks.

The second vulnerability was in the AsciiDoctor markup library.
AsciiDoctor was not properly including the 'noreferrer noopener'
options with external links. An internal investigation discovered
other markup libraries that were also vulnerable. Unauthorized
disclosure of wiki pages in search M. Hasbini reported a flaw in the
project search feature that allowed authenticated users to disclose
the contents of private wiki pages inside public projects. External
users can view internal snippets Christian Kuhn discovered a
vulnerability in GitLab snippets that allowed an external user to view
the contents of internal snippets. Subgroup visibility for private
subgroups under a public parent group Matt Harrison discovered a
vulnerability with subgroups that allowed private subgroup names to be
disclosed when they belong to a parent group that is public."
  );
  # https://about.gitlab.com/2017/05/08/gitlab-9-dot-1-dot-3-security-release/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?440bc105"
  );
  # http://www.freebsd.org/ports/portaudit/9704930c-3bb7-11e7-93f7-d43d7e971a1b.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9c7c5b22"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gitlab");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/08");
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

if (pkg_test(save_report:TRUE, pkg:"gitlab>=6.6.0<=8.17.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gitlab>=9.0.0<=9.0.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gitlab>=9.1.0<=9.1.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
