#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2015 Jacques Vidrine and contributors
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
  script_id(84254);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/05/16 16:21:30 $");

  script_cve_id("CVE-2015-3236", "CVE-2015-3237");

  script_name(english:"FreeBSD : cURL -- Multiple Vulnerability (2438d4af-1538-11e5-a106-3c970e169bc2)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"cURL reports :

libcurl can wrongly send HTTP credentials when re-using connections.

libcurl allows applications to set credentials for the upcoming
transfer with HTTP Basic authentication, like with CURLOPT_USERPWD for
example. Name and password. Just like all other libcurl options the
credentials are sticky and are kept associated with the 'handle' until
something is made to change the situation.

Further, libcurl offers a curl_easy_reset() function that resets a
handle back to its pristine state in terms of all settable options. A
reset is of course also supposed to clear the credentials. A reset is
typically used to clear up the handle and prepare it for a new,
possibly unrelated, transfer.

Within such a handle, libcurl can also store a set of previous
connections in case a second transfer is requested to a host name for
which an existing connection is already kept alive.

With this flaw present, using the handle even after a reset would make
libcurl accidentally use those credentials in a subseqent request if
done to the same host name and connection as was previously accessed.

An example case would be first requesting a password protected
resource from one section of a website, and then do a second request
of a public resource from a completely different part of the site
without authentication. This flaw would then inadvertently leak the
credentials in the second request.

libcurl can get tricked by a malicious SMB server to send off data it
did not intend to.

In libcurl's state machine function handling the SMB protocol
(smb_request_state()), two length and offset values are extracted from
data that has arrived over the network, and those values are
subsequently used to figure out what data range to send back.

The values are used and trusted without boundary checks and are just
assumed to be valid. This allows carefully handicrafted packages to
trick libcurl into responding and sending off data that was not
intended. Or just crash if the values cause libcurl to access invalid
memory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://curl.haxx.se/docs/adv_20150617A.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://curl.haxx.se/docs/adv_20150617B.html"
  );
  # http://www.freebsd.org/ports/portaudit/2438d4af-1538-11e5-a106-3c970e169bc2.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?93278fd4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"curl>=7.40<7.43")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
