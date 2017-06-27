#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2014 Jacques Vidrine and contributors
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
  script_id(21511);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/08/16 19:14:47 $");

  script_cve_id("CVE-2006-1502");
  script_xref(name:"Secunia", value:"19418");

  script_name(english:"FreeBSD : mplayer -- Multiple integer overflows (c7526a14-c4dc-11da-9699-00123ffe8333)");
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

The vulnerabilities are caused due to integer overflow errors in
'libmpdemux/asfheader.c' within the handling of an ASF file, and in
'libmpdemux/aviheader.c' when parsing the 'indx' chunk in an AVI file.
This can be exploited to cause heap-based buffer overflows via a
malicious ASF file, or via a AVI file with specially crafted
'wLongsPerEntry' and 'nEntriesInUse' values in the 'indx' chunk."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.xfocus.org/advisories/200603/11.html"
  );
  # http://www.freebsd.org/ports/portaudit/c7526a14-c4dc-11da-9699-00123ffe8333.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2fb7d571"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mplayer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mplayer-esound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mplayer-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mplayer-gtk-esound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mplayer-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mplayer-gtk2-esound");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"mplayer<0.99.7_12")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mplayer-esound<0.99.7_12")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mplayer-gtk<0.99.7_12")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mplayer-gtk2<0.99.7_12")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mplayer-gtk-esound<0.99.7_12")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mplayer-gtk2-esound<0.99.7_12")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
