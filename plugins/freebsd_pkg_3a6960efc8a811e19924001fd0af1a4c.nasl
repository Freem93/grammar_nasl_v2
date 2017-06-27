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
  script_id(59945);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/05/13 14:37:09 $");

  script_cve_id("CVE-2012-3864", "CVE-2012-3865", "CVE-2012-3866", "CVE-2012-3867");

  script_name(english:"FreeBSD : puppet -- multiple vulnerabilities (3a6960ef-c8a8-11e1-9924-001fd0af1a4c)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"puppet -- multiple vulnerabilities

Arbitrary file read on the puppet master from authenticated clients
(high). It is possible to construct an HTTP get request from an
authenticated client with a valid certificate that will return the
contents of an arbitrary file on the Puppet master that the master has
read-access to.

Arbitrary file delete/D.O.S on Puppet Master from authenticated
clients (high). Given a Puppet master with the 'Delete' directive
allowed in auth.conf for an authenticated host, an attacker on that
host can send a specially crafted Delete request that can cause an
arbitrary file deletion on the Puppet master, potentially causing a
denial of service attack. Note that this vulnerability does *not*
exist in Puppet as configured by default.

The last_run_report.yaml is world readable (medium). The most recent
Puppet run report is stored on the Puppet master with world-readable
permissions. The report file contains the context diffs of any changes
to configuration on an agent, which may contain sensitive information
that an attacker can then access. The last run report is overwritten
with every Puppet run.

Arbitrary file read on the Puppet master by an agent (medium). This
vulnerability is dependent upon vulnerability 'last_run_report.yml is
world readable' above. By creating a hard link of a Puppet-managed
file to an arbitrary file that the Puppet master can read, an attacker
forces the contents to be written to the puppet run summary. The
context diff is stored in last_run_report.yaml, which can then be
accessed by the attacker.

Insufficient input validation for agent hostnames (low). An attacker
could trick the administrator into signing an attacker's certificate
rather than the intended one by constructing specially crafted
certificate requests containing specific ANSI control sequences. It is
possible to use the sequences to rewrite the order of text displayed
to an administrator such that display of an invalid certificate and
valid certificate are transposed. If the administrator signs the
attacker's certificate, the attacker can then man-in-the-middle the
agent.

Agents with certnames of IP addresses can be impersonated (low). If an
authenticated host with a certname of an IP address changes IP
addresses, and a second host assumes the first host's former IP
address, the second host will be treated by the puppet master as the
first one, giving the second host access to the first host's catalog.
Note: This will not be fixed in Puppet versions prior to the
forthcoming 3.x. Instead, with this announcement IP-based
authentication in Puppet < 3.x is deprecated."
  );
  # http://projects.puppetlabs.com/projects/puppet/wiki/Release_Notes#2.7.18
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?70edb229"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://puppetlabs.com/security/cve/cve-2012-3864/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://puppetlabs.com/security/cve/cve-2012-3865/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://puppetlabs.com/security/cve/cve-2012-3866/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://puppetlabs.com/security/cve/cve-2012-3867/"
  );
  # http://www.freebsd.org/ports/portaudit/3a6960ef-c8a8-11e1-9924-001fd0af1a4c.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?43913dfd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:puppet");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"puppet>2.7.*<2.7.18")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
