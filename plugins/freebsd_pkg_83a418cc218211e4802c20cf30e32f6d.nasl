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
  script_id(77125);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/12/17 15:40:22 $");

  script_cve_id("CVE-2014-3522", "CVE-2014-3528");

  script_name(english:"FreeBSD : subversion -- several vulnerabilities (83a418cc-2182-11e4-802c-20cf30e32f6d)");
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
"Subversion Project reports :

Using the Serf RA layer of Subversion for HTTPS uses the apr_fnmatch
API to handle matching wildcards in certificate Common Names and
Subject Alternate Names. However, apr_fnmatch is not designed for this
purpose. Instead it is designed to behave like common shell globbing.
In particular this means that '*' is not limited to a single label
within a hostname (i.e. it will match '.'). But even further
apr_fnmatch supports '?' and character classes (neither of which are
part of the RFCs defining how certificate validation works).

Subversion stores cached credentials by an MD5 hash based on the URL
and the authentication realm of the server the credentials are cached
for. MD5 has been shown to be subject to chosen plaintext hash
collisions. This means it may be possible to generate an
authentication realm which results in the same MD5 hash for a
different URL."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.apache.org/security/CVE-2014-3522-advisory.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.apache.org/security/CVE-2014-3528-advisory.txt"
  );
  # http://www.freebsd.org/ports/portaudit/83a418cc-2182-11e4-802c-20cf30e32f6d.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5374d53f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:subversion16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:subversion17");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"subversion16>=1.0.0<1.7.18")) flag++;
if (pkg_test(save_report:TRUE, pkg:"subversion17>=1.0.0<1.7.18")) flag++;
if (pkg_test(save_report:TRUE, pkg:"subversion>=1.0.0<1.7.18")) flag++;
if (pkg_test(save_report:TRUE, pkg:"subversion>=1.8.0<1.8.10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
