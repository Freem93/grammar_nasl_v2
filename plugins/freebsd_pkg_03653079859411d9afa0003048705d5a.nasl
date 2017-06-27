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
  script_id(18824);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/09/18 13:33:38 $");

  script_name(english:"FreeBSD : phpbb -- multiple information disclosure vulnerabilities (03653079-8594-11d9-afa0-003048705d5a)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"psoTFX reports :

phpBB Group are pleased to announce the release of phpBB 2.0.12 the
'Horray for Furrywood' release. This release addresses a number of
bugs and a couple of potential exploits. [...] one of the potential
exploits addressed in this release could be serious in certain
situations and thus we urge all users, as always, to upgrade to this
release as soon as possible. Mostly this release is concerned with
eliminating disclosures of information which while useful in debug
situations may allow third parties to gain information which could be
used to do harm via unknown or unfixed exploits in this or other
applications.

The ChangeLog for phpBB 2.0.12 states :

- Prevented full path display on critical messages

- Fixed full path disclosure in username handling caused by a PHP
4.3.10 bug - AnthraX101

- Added exclude list to unsetting globals (if register_globals is on)
- SpoofedExistence

- Fixed arbitrary file disclosure vulnerability in avatar handling
functions - AnthraX101

- Fixed arbitrary file unlink vulnerability in avatar handling
functions - AnthraX101

- Fixed path disclosure bug in search.php caused by a PHP 4.3.10 bug
(related to AnthraX101's discovery)

- Fixed path disclosure bug in viewtopic.php caused by a PHP 4.3.10
bug - matrix_killer"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpbb.com/support/documents.php?mode=changelog"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpbb.com/phpBB/viewtopic.php?f=14&t=265423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=77943"
  );
  # http://www.freebsd.org/ports/portaudit/03653079-8594-11d9-afa0-003048705d5a.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8d399049"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpbb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"phpbb<2.0.12")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
