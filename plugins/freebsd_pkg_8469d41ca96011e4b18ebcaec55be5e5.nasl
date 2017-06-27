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
  script_id(81117);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/02/02 15:52:15 $");

  script_cve_id("CVE-2015-0862");

  script_name(english:"FreeBSD : rabbitmq -- Security issues in management plugin (8469d41c-a960-11e4-b18e-bcaec55be5e5)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The RabbitMQ project reports :

Some user-controllable content was not properly HTML-escaped before
being presented to a user in the management web UI :

- When a user unqueued a message from the management UI, message
details (header names, arguments, etc.) were displayed unescaped. An
attacker could publish a specially crafted message to add content or
execute arbitrary JavaScript code on behalf of a user, if this user
unqueued the message from the management UI.

- When viewing policies, their name was displayed unescaped. An
attacker could create a policy with a specially crafted name to add
content or execute arbitrary JavaScript code on behalf of a user who
is viewing policies.

- When listing connected AMQP network clients, client details such as
its version were displayed unescaped. An attacker could use a client
with a specially crafted version field to add content or execute
arbitrary JavaScript code on behalf of a user who is viewing connected
clients.

In all cases, the attacker needs a valid user account on the targetted
RabbitMQ cluster.

Furthermore, some admin-controllable content was not properly escaped
:

- user names;

- the cluster name.

Likewise, an attacker could add content or execute arbitrary
JavaScript code on behalf of a user using the management web UI.
However, the attacker must be an administrator on the RabbitMQ
cluster, thus a trusted user."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.rabbitmq.com/news.html#2015-01-08T10:14:05+0100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.rabbitmq.com/release-notes/README-3.4.3.txt"
  );
  # http://www.freebsd.org/ports/portaudit/8469d41c-a960-11e4-b18e-bcaec55be5e5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?246962e5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rabbitmq");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"rabbitmq<3.4.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:pkg_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
