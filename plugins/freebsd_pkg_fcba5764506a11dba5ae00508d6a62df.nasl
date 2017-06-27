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
  script_id(22492);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/06/22 00:15:02 $");

  script_cve_id("CVE-2006-4674", "CVE-2006-4675", "CVE-2006-4679");
  script_bugtraq_id(19911);
  script_xref(name:"Secunia", value:"21819");

  script_name(english:"FreeBSD : dokuwiki -- multiple vulnerabilities (fcba5764-506a-11db-a5ae-00508d6a62df)");
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

rgod has discovered a vulnerability in DokuWiki, which can be
exploited by malicious people to compromise a vulnerable system.

Input passed to the 'TARGET_FN' parameter in bin/dwpage.php is not
properly sanitised before being used to copy files. This can be
exploited via directory traversal attacks in combination with
DokuWiki's file upload feature to execute arbitrary PHP code.

CVE Mitre reports :

Direct static code injection vulnerability in doku.php in DokuWiki
before 2006-03-09c allows remote attackers to execute arbitrary PHP
code via the X-FORWARDED-FOR HTTP header, which is stored in
config.php.

Unrestricted file upload vulnerability in lib/exe/media.php in
DokuWiki before 2006-03-09c allows remote attackers to upload
executable files into the data/media folder via unspecified vectors.

DokuWiki before 2006-03-09c enables the debug feature by default,
which allows remote attackers to obtain sensitive information by
calling doku.php with the X-DOKUWIKI-DO HTTP header set to 'debug'."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.splitbrain.org/index.php?do=details&id=906"
  );
  # http://www.freebsd.org/ports/portaudit/fcba5764-506a-11db-a5ae-00508d6a62df.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4fd04e06"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:dokuwiki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:dokuwiki-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/08");
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

if (pkg_test(save_report:TRUE, pkg:"dokuwiki<20060309c")) flag++;
if (pkg_test(save_report:TRUE, pkg:"dokuwiki-devel<20060909")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
