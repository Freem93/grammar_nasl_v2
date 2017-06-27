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

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(72528);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/02/17 00:41:29 $");

  script_cve_id("CVE-2013-5573", "CVE-2013-7285");

  script_name(english:"FreeBSD : jenkins -- multiple vulnerabilities (3e0507c6-9614-11e3-b3a5-00e0814cab4e)");
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
"Jenkins Security Advisory reports :

This advisory announces multiple security vulnerabilities that were
found in Jenkins core.

- iSECURITY-105

In some places, Jenkins XML API uses XStream to deserialize arbitrary
content, which is affected by CVE-2013-7285 reported against XStream.
This allows malicious users of Jenkins with a limited set of
permissions to execute arbitrary code inside Jenkins master.

- SECURITY-76 & SECURITY-88 / CVE-2013-5573

Restrictions of HTML tags for user-editable contents are too lax. This
allows malicious users of Jenkins to trick other unsuspecting users
into providing sensitive information.

- SECURITY-109

Plugging a hole in the earlier fix to SECURITY-55. Under some
circimstances, a malicious user of Jenkins can configure job X to
trigger another job Y that the user has no access to.

- SECURITY-108

CLI job creation had a directory traversal vulnerability. This allows
a malicious user of Jenkins with a limited set of permissions to
overwrite files in the Jenkins master and escalate privileges.

- SECURITY-106

The embedded Winstone servlet container is susceptive to session
hijacking attack.

- SECURITY-93

The password input control in the password parameter definition in the
Jenkins UI was serving the actual value of the password in HTML, not
an encrypted one. If a sensitive value is set as the default value of
such a parameter definition, it can be exposed to unintended audience.

- SECURITY-89

Deleting the user was not invalidating the API token, allowing users
to access Jenkins when they shouldn't be allowed to do so.

- SECURITY-80

Jenkins UI was vulnerable to click jacking attacks.

- SECURITY-79

'Jenkins' own user database' was revealing the presence/absence of
users when login attempts fail.

- SECURITY-77

Jenkins had a cross-site scripting vulnerability in one of its
cookies. If Jenkins is deployed in an environment that allows an
attacker to override Jenkins cookies in victim's browser, this
vulnerability can be exploited.

- SECURITY-75

Jenkins was vulnerable to session fixation attack. If Jenkins is
deployed in an environment that allows an attacker to override Jenkins
cookies in victim's browser, this vulnerability can be exploited.

- SECURITY-74

Stored XSS vulnerability. A malicious user of Jenkins with a certain
set of permissions can cause Jenkins to store arbitrary HTML fragment.

- SECURITY-73

Some of the system diagnostic functionalities were checking a lesser
permission than it should have. In a very limited circumstances, this
can cause an attacker to gain information that he shouldn't have
access to.

Severity

- SECURITY-106, and SECURITY-80 are rated high. An attacker only needs
direct HTTP access to the server to mount this attack.

- SECURITY-105, SECURITY-109, SECURITY-108, and SECURITY-74 are rated
high. These vulnerabilities allow attackes with valid Jenkins user
accounts to escalate privileges in various ways.

- SECURITY-76, SECURIT-88, and SECURITY-89 are rated medium. These
vulnerabilities requires an attacker to be an user of Jenkins, and the
mode of the attack is limited.

- SECURITY-93, and SECURITY-79 are rated low. These vulnerabilities
only affect a small part of Jenkins and has limited impact.

- SECURITY-77, SECURITY-75, and SECURITY-73 are rated low. These
vulnerabilities are hard to exploit unless combined with other exploit
in the network."
  );
  # https://wiki.jenkins-ci.org/display/SECURITY/Jenkins+Security+Advisory+2014-02-14
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?45af4d96"
  );
  # http://www.freebsd.org/ports/portaudit/3e0507c6-9614-11e3-b3a5-00e0814cab4e.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f45e948"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:jenkins-lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/16");
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

if (pkg_test(save_report:TRUE, pkg:"jenkins<1.551")) flag++;
if (pkg_test(save_report:TRUE, pkg:"jenkins-lts<1.532.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
