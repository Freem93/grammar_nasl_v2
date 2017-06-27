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
  script_id(86268);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/10/06 13:33:40 $");

  script_cve_id("CVE-2015-7687");

  script_name(english:"FreeBSD : OpenSMTPD -- multiple vulnerabilities (ee7bdf7f-11bb-4eea-b054-c692ab848c20)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"OpenSMTPD developers report :

an oversight in the portable version of fgetln() that allows attackers
to read and write out-of-bounds memory

multiple denial-of-service vulnerabilities that allow local users to
kill or hang OpenSMTPD

a stack-based buffer overflow that allows local users to crash
OpenSMTPD, or execute arbitrary code as the non-chrooted _smtpd user

a hardlink attack (or race-conditioned symlink attack) that allows
local users to unset the chflags() of arbitrary files

a hardlink attack that allows local users to read the first line of
arbitrary files (for example, root's hash from /etc/master.passwd)

a denial-of-service vulnerability that allows remote attackers to fill
OpenSMTPD's queue or mailbox hard-disk partition

an out-of-bounds memory read that allows remote attackers to crash
OpenSMTPD, or leak information and defeat the ASLR protection

a use-after-free vulnerability that allows remote attackers to crash
OpenSMTPD, or execute arbitrary code as the non-chrooted _smtpd user"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.opensmtpd.org/announces/release-5.7.2.txt"
  );
  # http://www.freebsd.org/ports/portaudit/ee7bdf7f-11bb-4eea-b054-c692ab848c20.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?badf8e09"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:opensmtpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"opensmtpd<5.7.2,1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
