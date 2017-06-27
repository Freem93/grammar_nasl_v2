#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2013 Jacques Vidrine and contributors
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
  script_id(35283);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/06/21 23:43:35 $");

  script_cve_id("CVE-2008-3076");

  script_name(english:"FreeBSD : vim -- multiple vulnerabilities in the netrw module (0e1e3789-d87f-11dd-8ecd-00163e000016)");
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
"Jan Minar reports :

Applying the ``D'' to a file with a crafted file name, or inside a
directory with a crafted directory name, can lead to arbitrary code
execution.

Lack of sanitization throughout Netrw can lead to arbitrary code
execution upon opening a directory with a crafted name.

The Vim Netrw Plugin shares the FTP user name and password across all
FTP sessions. Every time Vim makes a new FTP connection, it sends the
user name and password of the previous FTP session to the FTP server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openwall.com/lists/oss-security/2008/10/16/2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.rdancer.org/vulnerablevim-netrw.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.rdancer.org/vulnerablevim-netrw.v2.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.rdancer.org/vulnerablevim-netrw.v5.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.rdancer.org/vulnerablevim-netrw-credentials-dis.html"
  );
  # http://www.freebsd.org/ports/portaudit/0e1e3789-d87f-11dd-8ecd-00163e000016.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?813c72a8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(78);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:vim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:vim-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:vim-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:vim-lite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"vim>=7.0<7.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"vim-lite>=7.0<7.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"vim-gtk2>=7.0<7.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"vim-gnome>=7.0<7.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
