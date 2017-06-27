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
  script_id(19015);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/08/09 10:50:39 $");

  script_cve_id("CVE-2004-1284");
  script_bugtraq_id(11958);
  script_xref(name:"Secunia", value:"13511");

  script_name(english:"FreeBSD : mpg123 -- playlist processing buffer overflow vulnerability (877e918e-5362-11d9-96d4-00065be4b5b6)");
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
"A buffer overflow vulnerability exists in the playlist processing of
mpg123. A specially crafted playlist entry can cause a stack overflow
that can be used to inject arbitrary code into the mpg123 process.

Note that a malicious playlist, demonstrating this vulnerability, was
released by the bug finder and may be used as a template by attackers."
  );
  # http://tigger.uic.edu/~jlongs2/holes/mpg123.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?484e5d15"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://xforce.iss.net/xforce/xfdb/18626"
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=110321888413132
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=bugtraq&m=110321888413132"
  );
  # http://www.freebsd.org/ports/portaudit/877e918e-5362-11d9-96d4-00065be4b5b6.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2569f17"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mpg123");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mpg123-esound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mpg123-nas");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"mpg123<=0.59r_15")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mpg123-nas<=0.59r_15")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mpg123-esound<=0.59r_15")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
