#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2017 Jacques Vidrine and contributors
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
  script_id(88068);
  script_version("$Revision: 2.12 $");
  script_cvs_date("$Date: 2017/02/13 20:45:09 $");

  script_cve_id("CVE-2015-7973", "CVE-2015-7974", "CVE-2015-7975", "CVE-2015-7976", "CVE-2015-7977", "CVE-2015-7978", "CVE-2015-7979", "CVE-2015-8138", "CVE-2015-8139", "CVE-2015-8140", "CVE-2015-8158");
  script_xref(name:"FreeBSD", value:"SA-16:09.ntp");

  script_name(english:"FreeBSD : ntp -- multiple vulnerabilities (5237f5d7-c020-11e5-b397-d050996490d0)");
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
"Network Time Foundation reports :

NTF's NTP Project has been notified of the following low- and
medium-severity vulnerabilities that are fixed in ntp-4.2.8p6,
released on Tuesday, 19 January 2016 :

- Bug 2948 / CVE-2015-8158: Potential Infinite Loop in ntpq. Reported
by Cisco ASIG.

- Bug 2945 / CVE-2015-8138: origin: Zero Origin Timestamp Bypass.
Reported by Cisco ASIG.

- Bug 2942 / CVE-2015-7979: Off-path Denial of Service (DoS) attack on
authenticated broadcast mode. Reported by Cisco ASIG.

- Bug 2940 / CVE-2015-7978: Stack exhaustion in recursive traversal of
restriction list. Reported by Cisco ASIG.

- Bug 2939 / CVE-2015-7977: reslist NULL pointer dereference. Reported
by Cisco ASIG.

- Bug 2938 / CVE-2015-7976: ntpq saveconfig command allows dangerous
characters in filenames. Reported by Cisco ASIG.

- Bug 2937 / CVE-2015-7975: nextvar() missing length check. Reported
by Cisco ASIG.

- Bug 2936 / CVE-2015-7974: Skeleton Key: Missing key check allows
impersonation between authenticated peers. Reported by Cisco ASIG.

- Bug 2935 / CVE-2015-7973: Deja Vu: Replay attack on authenticated
broadcast mode. Reported by Cisco ASIG.

Additionally, mitigations are published for the following two issues :

- Bug 2947 / CVE-2015-8140: ntpq vulnerable to replay attacks.
Reported by Cisco ASIG.

- Bug 2946 / CVE-2015-8139: Origin Leak: ntpq and ntpdc, disclose
origin. Reported by Cisco ASIG."
  );
  # http://support.ntp.org/bin/view/Main/SecurityNotice#January_2016_NTP_4_2_8p6_Securit
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d42322ca"
  );
  # http://www.freebsd.org/ports/portaudit/5237f5d7-c020-11e5-b397-d050996490d0.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5469abda"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ntp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"ntp<4.2.8p6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ntp-devel<4.3.90")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
