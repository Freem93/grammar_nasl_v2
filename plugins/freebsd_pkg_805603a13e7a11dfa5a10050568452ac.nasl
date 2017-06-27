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
  script_id(45446);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/08/13 14:23:43 $");

  script_xref(name:"Secunia", value:"38964");

  script_name(english:"FreeBSD : dojo -- XSS and other vulnerabilities (805603a1-3e7a-11df-a5a1-0050568452ac)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Dojo Toolkit team reports :

Some PHP files did not properly escape input.

Some files could operate like 'open redirects'. A bad actor could form
an URL that looks like it came from a trusted site, but the user would
be redirected or load content from the bad actor's site.

A file exposed a more serious cross-site scripting vulnerability with
the possibility of executing code on the domain where the file exists.

The Dojo build process defaulted to copying over tests and demos,
which are normally not needed and just increased the number of files
that could be targets of attacks."
  );
  # http://dojotoolkit.org/blog/post/dylan/2010/03/dojo-security-advisory/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9e6d2114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://osdir.com/ml/bugtraq.security/2010-03/msg00133.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://packetstormsecurity.org/1003-exploits/dojo-xss.txt"
  );
  # http://www.gdssecurity.com/l/b/2010/03/12/multiple-dom-based-xss-in-dojo-toolkit-sdk/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?670dde7c"
  );
  # http://www.freebsd.org/ports/portaudit/805603a1-3e7a-11df-a5a1-0050568452ac.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a678d8d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:dojo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"dojo<1.4.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
