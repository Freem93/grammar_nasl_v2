# @DEPRECATED@
#
# This script has been deprecated as it duplicates
# freebsd_pkg_36235c38e0a811e19f4d002354ed89bc.nasl
#
# Disabled on 2012/08/15.
#

#
# (C) Tenable Network Security, Inc.
#
# This script contains information extracted from VuXML :
#
# Copyright 2003-2012 Jacques Vidrine and contributors
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
  script_id(61444);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/08/15 16:40:25 $");

  script_cve_id("CVE-2012-3386");

  script_name(english:"FreeBSD : automake -- Insecure 'distcheck' recipe granted world-writable distdir (10f38033-e006-11e1-9304-000000000000)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"GNU reports :

The recipe of the 'distcheck' target granted temporary world-write
permissions on the extracted distdir. This introduced a locally
exploitable race condition for those who run 'make distcheck' with a
non-restrictive umask (e.g., 022) in a directory that was accessible
by others. A successful exploit would result in arbitrary code
execution with the privileges of the user running 'make distcheck'.

It is important to stress that this vulnerability impacts not only the
Automake package itself, but all packages with Automake-generated
makefiles. For an effective fix it is necessary to regenerate the
Makefile.in files with a fixed Automake version."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.gnu.org/archive/html/automake/2012-07/msg00023.html"
  );
  # http://www.freebsd.org/ports/portaudit/10f38033-e006-11e1-9304-000000000000.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?44656775"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is (C) 2012 Tenable Network Security, Inc.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}

# Deprecated.
exit(0, "This patch duplicates plugin #61451 (freebsd_pkg_36235c38e0a811e19f4d002354ed89bc.nasl).");

include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/FreeBSD/release")) exit(0, "The host is not running FreeBSD.");
if (!get_kb_item("Host/FreeBSD/pkg_info")) exit(1, "Could not obtain the list of installed packages.");


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"automake<1.12.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
