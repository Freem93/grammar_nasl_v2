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
  script_id(35625);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/08 20:31:55 $");

  script_cve_id("CVE-2008-5918", "CVE-2008-5919", "CVE-2009-0240");
  script_xref(name:"Secunia", value:"32338");

  script_name(english:"FreeBSD : websvn -- multiple vulnerabilities (71597e3e-f6b8-11dd-94d9-0030843d3802)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Secunia reports :

Some vulnerabilities have been reported in WebSVN, which can be
exploited by malicious users to disclose sensitive information, and by
malicious people to conduct cross-site scripting attacks and
manipulate data.

Input passed in the URL to index.php is not properly sanitised before
being returned to the user. This can be exploited to execute arbitrary
HTML and script code in a user's browser session in context of an
affected site.

Input passed to the 'rev' parameter in rss.php is not properly
sanitised before being used. This can be exploited to overwrite
arbitrary files via directory traversal attacks.

Access to restricted repositories is not properly enforced, which can
be exploited to disclose potentially sensitive information by
accessing the repository via 'listing.php' and using the 'compare with
previous' and 'show changed files' links."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=512191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gulftech.org/?node=research&article_id=00132-10202008"
  );
  # http://www.freebsd.org/ports/portaudit/71597e3e-f6b8-11dd-94d9-0030843d3802.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9404b0f1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(22, 79, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:websvn");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/09");
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

if (pkg_test(save_report:TRUE, pkg:"websvn<2.1.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
