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

include("compat.inc");

if (description)
{
  script_id(18990);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/08 20:31:56 $");

  script_cve_id("CVE-2004-1268", "CVE-2004-1269", "CVE-2004-1270");
  script_bugtraq_id(12004, 12007);

  script_name(english:"FreeBSD : cups-lpr -- lppasswd multiple vulnerabilities (7850a238-680a-11d9-a9e7-0001020eed82)");
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
"D. J. Bernstein reports that Bartlomiej Sieka has discovered several
security vulnerabilities in lppasswd, which is part of CUPS. In the
following excerpt from Bernstein's email, CVE names have been added
for each issue :

First, lppasswd blithely ignores write errors in fputs(line,outfile)
at lines 311 and 315 of lppasswd.c, and in fprintf(...) at line 346.
An attacker who fills up the disk at the right moment can arrange for
/usr/local/etc/cups/passwd to be truncated. (CAN-2004-1268)

Second, if lppasswd bumps into a file-size resource limit while
writing passwd.new, it leaves passwd.new in place, disabling all
subsequent invocations of lppasswd. Any local user can thus disable
lppasswd... (CAN-2004-1269)

Third, line 306 of lppasswd.c prints an error message to stderr but
does not exit. This is not a problem on systems that ensure that file
descriptors 0, 1, and 2 are open for setuid programs, but it is a
problem on other systems; lppasswd does not check that passwd.new is
different from stderr, so it ends up writing a user-controlled error
message to passwd if the user closes file descriptor 2.
(CAN-2004-1270)

Note: The third issue, CVE-2004-1270, does not affect FreeBSD
4.6-RELEASE or later systems, as these systems ensure that the file
descriptors 0, 1, and 2 are always open for set-user-ID and
set-group-ID programs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.cups.org/str.php?L1023"
  );
  # http://tigger.uic.edu/~jlongs2/holes/cups2.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?afff57c3"
  );
  # http://www.freebsd.org/ports/portaudit/7850a238-680a-11d9-a9e7-0001020eed82.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bbff3d7b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:cups-lpr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:fr-cups-lpr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"cups-lpr<1.1.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"fr-cups-lpr<1.1.23")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
