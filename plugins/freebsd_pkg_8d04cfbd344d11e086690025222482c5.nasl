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
  script_id(51915);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/06/22 00:02:02 $");

  script_cve_id("CVE-2011-0047");

  script_name(english:"FreeBSD : mediawiki -- multiple vulnerabilities (8d04cfbd-344d-11e0-8669-0025222482c5)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Medawiki reports :

An arbitrary script inclusion vulnerability was discovered. The
vulnerability only allows execution of files with names ending in
'.php' which are already present in the local filesystem. Only servers
running Microsoft Windows and possibly Novell Netware are affected.
Despite these mitigating factors, all users are advised to upgrade,
since there is a risk of complete server compromise. MediaWiki 1.8.0
and later is affected.

Security researcher mghack discovered a CSS injection vulnerability.
For Internet Explorer and similar browsers, this is equivalent to an
XSS vulnerability, that is to say, it allows the compromise of wiki
user accounts. For other browsers, it allows private data such as IP
addresses and browsing patterns to be sent to a malicious external web
server. It affects all versions of MediaWiki. All users are advised to
upgrade."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=27094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=27093"
  );
  # http://svn.wikimedia.org/svnroot/mediawiki/tags/REL1_16_2/phase3/RELEASE-NOTES
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d631580"
  );
  # http://lists.wikimedia.org/pipermail/mediawiki-announce/2011-February/000095.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c3c879f"
  );
  # http://www.freebsd.org/ports/portaudit/8d04cfbd-344d-11e0-8669-0025222482c5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cadc4174"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mediawiki");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"mediawiki<1.16.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
