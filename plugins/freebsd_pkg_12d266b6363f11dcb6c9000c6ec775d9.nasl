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
  script_id(25748);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/06/21 23:43:35 $");

  script_cve_id("CVE-2007-3929", "CVE-2007-4944");

  script_name(english:"FreeBSD : opera -- multiple vulnerabilities (12d266b6-363f-11dc-b6c9-000c6ec775d9)");
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
"Opera Software ASA reports of multiple security fixes in Opera,
including an arbitrary code execute vulnerability :

Opera for Linux, FreeBSD, and Solaris has a flaw in the createPattern
function that leaves old data that was in the memory before Opera
allocated it in the new pattern. The pattern can be read and analyzed
by JavaScript, so an attacker can get random samples of the user's
memory, which may contain data.

Removing a specially crafted torrent from the download manager can
crash Opera. The crash is caused by an erroneous memory access.

An attacker needs to entice the user to accept the malicious
BitTorrent download, and later remove it from Opera's download
manager. To inject code, additional means will have to be employed.

Users clicking a BitTorrent link and rejecting the download are not
affected.

data: URLs embed data inside them, instead of linking to an external
resource. Opera can mistakenly display the end of a data URL instead
of the beginning. This allows an attacker to spoof the URL of a
trusted site.

Opera's HTTP authentication dialog is displayed when the user enters a
Web page that requires a login name and a password. To inform the user
which server it was that asked for login credentials, the dialog
displays the server name.

The user has to see the entire server name. A truncated name can be
misleading. Opera's authentication dialog cuts off the long server
names at the right hand side, adding an ellipsis (...) to indicate
that it has been cut off.

The dialog has a predictable size, allowing an attacker to create a
server name which will look almost like a trusted site, because the
real domain name has been cut off. The three dots at the end will not
be obvious to all users.

This flaw can be exploited by phishers who can set up custom
sub-domains, for example by hosting their own public DNS."
  );
  # http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=564
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?21ab0334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.opera.com/support/search/view/861/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.opera.com/support/search/view/862/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.opera.com/support/search/view/863/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.opera.com/support/search/view/864/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.opera.com/docs/changelogs/freebsd/922/"
  );
  # http://www.freebsd.org/ports/portaudit/12d266b6-363f-11dc-b6c9-000c6ec775d9.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2f78f15"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-opera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:opera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:opera-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"opera<9.22")) flag++;
if (pkg_test(save_report:TRUE, pkg:"opera-devel<9.22")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-opera<9.22")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
