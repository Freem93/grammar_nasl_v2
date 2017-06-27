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
  script_id(37427);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/01/14 15:20:32 $");

  script_cve_id("CVE-2004-0414", "CVE-2004-0416", "CVE-2004-0417", "CVE-2004-0418", "CVE-2004-0778");
  script_bugtraq_id(10499);
  script_osvdb_id(6830, 6831, 6832, 6833, 6834, 6835, 6836, 8977);
  script_xref(name:"FreeBSD", value:"SA-04:14.cvs");
  script_xref(name:"Secunia", value:"11817");
  script_xref(name:"Secunia", value:"12309");

  script_name(english:"FreeBSD : cvs -- numerous vulnerabilities (d2102505-f03d-11d8-81b0-000347a4fa7d)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A number of vulnerabilities were discovered in CVS by Stefan Esser,
Sebastian Krahmer, and Derek Price.

- Insufficient input validation while processing 'Entry' lines.
(CVE-2004-0414)

- A double-free resulting from erroneous state handling while
processing 'Argumentx' commands. (CVE-2004-0416)

- Integer overflow while processing 'Max-dotdot' commands.
(CVE-2004-0417)

- Erroneous handling of empty entries handled while processing
'Notify' commands. (CVE-2004-0418)

- A format string bug while processing CVS wrappers.

- Single-byte buffer underflows while processing configuration files
from CVSROOT.

- Various other integer overflows.

Additionally, iDEFENSE reports an undocumented command-line flag used
in debugging does not perform input validation on the given path
names.

CVS servers ('cvs server' or :pserver: modes) are affected by these
vulnerabilities. They vary in impact but include information
disclosure (the iDEFENSE-reported bug), denial-of-service
(CVE-2004-0414, CVE-2004-0416, CVE-2004-0417 and other bugs), or
possibly arbitrary code execution (CVE-2004-0418). In very special
situations where the attacker may somehow influence the contents of
CVS configuration files in CVSROOT, additional attacks may be
possible."
  );
  # http://security.e-matters.de/advisories/092004.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1215cc0e"
  );
  # http://www.idefense.com/application/poi/display?id=130&type=vulnerabilities&flashstatus=false
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4b00c0a7"
  );
  # http://www.freebsd.org/ports/portaudit/d2102505-f03d-11d8-81b0-000347a4fa7d.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1b24c7af"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:cvs+ipv6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"cvs+ipv6<1.11.17")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
