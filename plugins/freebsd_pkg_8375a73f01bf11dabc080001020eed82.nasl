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
  script_id(19349);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/06/22 00:02:01 $");

  script_cve_id("CVE-2005-0366");
  script_xref(name:"CERT", value:"303094");

  script_name(english:"FreeBSD : gnupg -- OpenPGP symmetric encryption vulnerability (8375a73f-01bf-11da-bc08-0001020eed82)");
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
"Serge Mister and Robert Zuccherato reports that the OpenPGP protocol
is vulnerable to a cryptographic attack when using symmetric
encryption in an automated way.

David Shaw reports about the impact :

This attack, while very significant from a cryptographic point of
view, is not generally effective in the real world. To be specific,
unless you have your OpenPGP program set up as part of an automated
system to accept encrypted messages, decrypt them, and then provide a
response to the submitter, then this does not affect you at all.

Note that the fix in GnuPG does note completely eliminate the
potential problem :

These patches disable a portion of the OpenPGP protocol that the
attack is exploiting. This change should not be user visible. With the
patch in place, this attack will not work using a public-key encrypted
message. It will still work using a passphrase-encrypted message."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://eprint.iacr.org/2005/033"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.gnupg.org/pipermail/gnupg-announce/2005q1/000191.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.pgp.com/newsroom/ctocorner/openpgp.html"
  );
  # http://www.freebsd.org/ports/portaudit/8375a73f-01bf-11da-bc08-0001020eed82.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7addd2dc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gnupg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:p5-Crypt-OpenPGP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:pgp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/01");
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

if (pkg_test(save_report:TRUE, pkg:"gnupg<1.4.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"p5-Crypt-OpenPGP<=1.03")) flag++;
if (pkg_test(save_report:TRUE, pkg:"pgp>=3.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
