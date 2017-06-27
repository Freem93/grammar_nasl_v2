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

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(78017);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/09/01 13:14:18 $");

  script_cve_id("CVE-2013-2186", "CVE-2014-1869", "CVE-2014-3661", "CVE-2014-3662", "CVE-2014-3663", "CVE-2014-3664", "CVE-2014-3666", "CVE-2014-3667", "CVE-2014-3678", "CVE-2014-3679", "CVE-2014-3680", "CVE-2014-3681");
  script_xref(name:"TRA", value:"TRA-2016-23");

  script_name(english:"FreeBSD : jenkins -- remote execution, privilege escalation, XSS, password exposure, ACL hole, DoS (549a2771-49cc-11e4-ae2c-c80aa9043978)");
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
"Jenkins Security Advisory : DescriptionSECURITY-87/CVE-2014-3661
(anonymous DoS attack through CLI handshake) This vulnerability allows
unauthenticated users with access to Jenkins' HTTP/HTTPS port to mount
a DoS attack on Jenkins through thread exhaustion.
SECURITY-110/CVE-2014-3662 (User name discovery) Anonymous users can
test if the user of a specific name exists or not through login
attempts. SECURITY-127&128/CVE-2014-3663 (privilege escalation in job
configuration permission) An user with a permission limited to
Job/CONFIGURE can exploit this vulnerability to effectively create a
new job, which should have been only possible for users with
Job/CREATE permission, or to destroy jobs that he/she does not have
access otherwise. SECURITY-131/CVE-2014-3664 (directory traversal
attack) Users with Overall/READ permission can access arbitrary files
in the file system readable by the Jenkins process, resulting in the
exposure of sensitive information, such as encryption keys.
SECURITY-138/CVE-2014-3680 (Password exposure in DOM) If a
parameterized job has a default value in a password field, that
default value gets exposed to users with Job/READ permission.

SECURITY-143/CVE-2014-3681 (XSS vulnerability in Jenkins core)
Reflected cross-site scripting vulnerability in Jenkins core. An
attacker can navigate the user to a carefully crafted URL and have the
user execute unintended actions. SECURITY-150/CVE-2014-3666 (remote
code execution from CLI) Unauthenticated user can execute arbitrary
code on Jenkins master by sending carefully crafted packets over the
CLI channel. SECURITY-155/CVE-2014-3667 (exposure of plugin code)
Programs that constitute plugins can be downloaded by anyone with the
Overall/READ permission, resulting in the exposure of otherwise
sensitive information, such as hard-coded keys in plugins, if any.
SECURITY-159/CVE-2013-2186 (arbitrary file system write) Security
vulnerability in commons fileupload allows unauthenticated attacker to
upload arbitrary files to Jenkins master. SECURITY-149/CVE-2014-1869
(XSS vulnerabilities in ZeroClipboard) reflective XSS vulnerability in
one of the library dependencies of Jenkins. SECURITY-113/CVE-2014-3678
(XSS vulnerabilities in monitoring plugin) Monitoring plugin allows an
attacker to cause a victim into executing unwanted actions on Jenkins
instance. SECURITY-113/CVE-2014-3679 (hole in access control) Certain
pages in monitoring plugin are visible to anonymous users, allowing
them to gain information that they are not supposed to.

Severity SECURITY-87 is rated medium, as it results in the loss of
functionality.

SECURITY-110 is rated medium, as it results in a limited amount of
information exposure.

SECURITY-127 and SECURITY-128 are rated high. The formed can be used
to further escalate privileges, and the latter results inloss of data.

SECURITY-131 and SECURITY-138 is rated critical. This vulnerabilities
results in exposure of sensitie information and is easily exploitable.

SECURITY-143 is rated high. It is a passive attack, but it can result
in a compromise of Jenkins master or loss of data.

SECURITY-150 is rated critical. This attack can be mounted by any
unauthenticated anonymous user with HTTP reachability to Jenkins
instance, and results in remote code execution on Jenkins.

SECURITY-155 is rated medium. This only affects users who have
installed proprietary plugins on publicly accessible instances, which
is relatively uncommon.

SECURITY-159 is rated critical. This attack can be mounted by any
unauthenticated anonymous user with HTTP reachability to Jenkins
instance.

SECURITY-113 is rated high. It is a passive attack, but it can result
in a compromise of Jenkins master or loss of data."
  );
  # https://wiki.jenkins-ci.org/display/SECURITY/Jenkins+Security+Advisory+2014-10-01
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1236c16f"
  );
  # http://www.freebsd.org/ports/portaudit/549a2771-49cc-11e4-ae2c-c80aa9043978.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e42f900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2016-23"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:jenkins-lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"jenkins<1.583")) flag++;
if (pkg_test(save_report:TRUE, pkg:"jenkins-lts<1.565.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
