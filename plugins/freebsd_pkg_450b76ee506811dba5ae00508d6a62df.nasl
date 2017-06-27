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
  script_id(22489);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/06/21 23:52:43 $");

  script_cve_id("CVE-2006-5098", "CVE-2006-5099");
  script_xref(name:"Secunia", value:"22192");
  script_xref(name:"Secunia", value:"22199");

  script_name(english:"FreeBSD : dokuwiki -- multiple vulnerabilities (450b76ee-5068-11db-a5ae-00508d6a62df)");
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
"Secunia reports :

Some vulnerabilities have been reported in DokuWiki, which can be
exploited by malicious people to cause a DoS (Denial of Service) or
potentially compromise a vulnerable system.

Input passed to the 'w' and 'h' parameters in lib/exec/fetch.php is
not properly sanitised before being passed as resize parameters to the
'convert' application. This can be exploited to cause a DoS due to
excessive CPU and memory consumption by passing very large numbers, or
to inject arbitrary shell commands by passing specially crafted
strings to the 'w' and 'h' parameter.

Successful exploitation requires that the '$conf[imconvert]' option is
set."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.splitbrain.org/?do=details&id=924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.splitbrain.org/?do=details&id=926"
  );
  # http://www.freebsd.org/ports/portaudit/450b76ee-5068-11db-a5ae-00508d6a62df.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0c44e3ad"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:dokuwiki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:dokuwiki-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"dokuwiki<20060309_5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"dokuwiki-devel<20060609_2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
