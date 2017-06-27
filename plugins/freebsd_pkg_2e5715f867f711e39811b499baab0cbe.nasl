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
  script_id(71529);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/12/24 21:55:42 $");

  script_cve_id("CVE-2013-4576");

  script_name(english:"FreeBSD : gnupg -- RSA Key Extraction via Low-Bandwidth Acoustic Cryptanalysis attack (2e5715f8-67f7-11e3-9811-b499baab0cbe)");
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
"Werner Koch reports :

CVE-2013-4576 has been assigned to this security bug.

The paper describes two attacks. The first attack allows to
distinguish keys: An attacker is able to notice which key is currently
used for decryption. This is in general not a problem but may be used
to reveal the information that a message, encrypted to a commonly not
used key, has been received by the targeted machine. We do not have a
software solution to mitigate this attack.

The second attack is more serious. It is an adaptive chosen ciphertext
attack to reveal the private key. A possible scenario is that the
attacker places a sensor (for example a standard smartphone) in the
vicinity of the targeted machine. That machine is assumed to do
unattended RSA decryption of received mails, for example by using a
mail client which speeds up browsing by opportunistically decrypting
mails expected to be read soon. While listening to the acoustic
emanations of the targeted machine, the smartphone will send new
encrypted messages to that machine and re-construct the private key
bit by bit. A 4096 bit RSA key used on a laptop can be revealed within
an hour."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.gnupg.org/pipermail/gnupg-announce/2013q4/000337.html"
  );
  # http://www.freebsd.org/ports/portaudit/2e5715f8-67f7-11e3-9811-b499baab0cbe.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?152e0098"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gnupg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gnupg1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"gnupg<1.4.16")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gnupg1<1.4.16")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:pkg_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
