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
  script_id(36240);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/06/22 00:10:42 $");

  script_cve_id("CVE-2004-0794");
  script_bugtraq_id(10967);

  script_name(english:"FreeBSD : tnftpd -- remotely exploitable vulnerability (c4b025bb-f05d-11d8-9837-000c41e2cdad)");
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
"lukemftpd(8) is an enhanced BSD FTP server produced within the NetBSD
project. The sources for lukemftpd are shipped with some versions of
FreeBSD, however it is not built or installed by default. The build
system option WANT_LUKEMFTPD must be set to build and install
lukemftpd. [NOTE: An exception is FreeBSD 4.7-RELEASE, wherein
lukemftpd was installed, but not enabled, by default.]

Przemyslaw Frasunek discovered several vulnerabilities in lukemftpd
arising from races in the out-of-band signal handling code used to
implement the ABOR command. As a result of these races, the internal
state of the FTP server may be manipulated in unexpected ways.

A remote attacker may be able to cause FTP commands to be executed
with the privileges of the running lukemftpd process. This may be a
low-privilege `ftp' user if the `-r' command line option is specified,
or it may be superuser privileges if `-r' is *not* specified."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cvsweb.netbsd.org/bsdweb.cgi/src/libexec/ftpd/ftpd.c#rev1.158"
  );
  # ftp://ftp.netbsd.org/pub/NetBSD/security/advisories/NetBSD-SA2004-009.txt.asc
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f8313496"
  );
  # http://lists.netsys.com/pipermail/full-disclosure/2004-August/025418.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0167350a"
  );
  # http://www.freebsd.org/ports/portaudit/c4b025bb-f05d-11d8-9837-000c41e2cdad.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f143a77"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:lukemftpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tnftpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"tnftpd<20040810")) flag++;
if (pkg_test(save_report:TRUE, pkg:"lukemftpd>=0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
