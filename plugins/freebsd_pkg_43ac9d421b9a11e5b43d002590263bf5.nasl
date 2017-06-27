#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2016 Jacques Vidrine and contributors
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

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(84411);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/05/20 14:02:59 $");

  script_cve_id("CVE-2014-3120");
  script_bugtraq_id(67731);
  script_xref(name:"EDB-ID", value:"33370");

  script_name(english:"FreeBSD : elasticsearch and logstash -- remote OS command execution via dynamic scripting (43ac9d42-1b9a-11e5-b43d-002590263bf5)");
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
"Elastic reports :

Vulnerability Summary: In Elasticsearch versions 1.1.x and prior,
dynamic scripting is enabled by default. This could allow an attacker
to execute OS commands.

Remediation Summary: Disable dynamic scripting.

Logstash 1.4.2 was bundled with Elasticsearch 1.1.1, which is
vulnerable to CVE-2014-3120. These binaries are used in Elasticsearch
output specifically when using the node protocol. Since a node client
joins the Elasticsearch cluster, the attackers could use scripts to
execute commands on the host OS using the node client's URL endpoint.
With 1.4.3 release, we are packaging Logstash with Elasticsearch 1.5.2
binaries which by default disables the ability to run scripts. This
also affects users who are using the configuration option
embedded=>true in the Elasticsearch output which starts a local
embedded Elasticsearch cluster. This is typically used in development
environment and proof of concept deployments. Regardless of this
vulnerability, we strongly recommend not using embedded in production.

Note that users of transport and http protocol are not vulnerable to
this attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.elastic.co/community/security"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.elastic.co/blog/elasticsearch-1-2-0-released"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.elastic.co/blog/logstash-1-4-3-released"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bouk.co/blog/elasticsearch-rce/"
  );
  # http://www.rapid7.com/db/modules/exploit/multi/elasticsearch/script_mvel_rce
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6b654c41"
  );
  # https://www.found.no/foundation/elasticsearch-security/#staying-safe-while-developing-with-elasticsearch
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6702767b"
  );
  # http://www.freebsd.org/ports/portaudit/43ac9d42-1b9a-11e5-b43d-002590263bf5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24cc3882"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ElasticSearch Dynamic Script Arbitrary Java Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:logstash");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/26");
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

if (pkg_test(save_report:TRUE, pkg:"elasticsearch<1.2.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"logstash<1.4.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
