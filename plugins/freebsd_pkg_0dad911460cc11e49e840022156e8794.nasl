#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2015 Jacques Vidrine and contributors
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
  script_id(78815);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/11/30 15:53:21 $");

  script_cve_id("CVE-2014-3665");

  script_name(english:"FreeBSD : jenkins -- slave-originated arbitrary code execution on master servers (0dad9114-60cc-11e4-9e84-0022156e8794)");
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
"Kohsuke Kawaguchi from Jenkins team reports :

Historically, Jenkins master and slaves behaved as if they altogether
form a single distributed process. This means a slave can ask a master
to do just about anything within the confinement of the operating
system, such as accessing files on the master or trigger other jobs on
Jenkins.

This has increasingly become problematic, as larger enterprise
deployments have developed more sophisticated trust separation model,
where the administators of a master might take slaves owned by other
teams. In such an environment, slaves are less trusted than the
master. Yet the 'single distributed process' assumption was not
communicated well to the users, resulting in vulnerabilities in some
deployments.

SECURITY-144 (CVE-2014-3665) introduces a new subsystem to address
this problem. This feature is off by default for compatibility
reasons. See Wiki for more details, who should turn this on, and
implications.

CVE-2014-3566 is rated high. It only affects installations that accept
slaves from less trusted computers, but this will allow an owner of of
such slave to mount a remote code execution attack on Jenkins."
  );
  # https://wiki.jenkins-ci.org/display/SECURITY/Jenkins+Security+Advisory+2014-10-30
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c3ec4fdc"
  );
  # https://wiki.jenkins-ci.org/display/JENKINS/Slave+To+Master+Access+Control
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ea19aad"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.cloudbees.com/jenkins-security-advisory-2014-10-30"
  );
  # http://www.freebsd.org/ports/portaudit/0dad9114-60cc-11e4-9e84-0022156e8794.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?99e73170"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:jenkins-lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"jenkins<1.587")) flag++;
if (pkg_test(save_report:TRUE, pkg:"jenkins-lts<1.580.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
