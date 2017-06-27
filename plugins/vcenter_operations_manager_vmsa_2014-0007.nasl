#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76388);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/08/16 14:42:21 $");

  script_cve_id("CVE-2014-0050", "CVE-2014-0094", "CVE-2014-0112");
  script_bugtraq_id(65400, 65999, 67064);
  script_osvdb_id(102945, 103918);
  script_xref(name:"VMSA", value:"2014-0007");
  script_xref(name:"IAVB", value:"2014-B-0090");

  script_name(english:"VMware vCenter Operations Management Suite Multiple Vulnerabilities (VMSA-2014-0007)");
  script_summary(english:"Checks version of vCenter Operations Manager.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization appliance installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of vCenter Operations Manager installed on the remote host
is prior to 5.8.2. It is, therefore, affected by the following
vulnerabilities :

  - An error exists in the included Apache Tomcat version
    related to handling 'Content-Type' HTTP headers and
    multipart requests such as file uploads that could
    allow denial of service attacks. (CVE-2014-0050)

  - A security bypass error exists due to the included
    Apache Struts2 component, allowing manipulation of the
    ClassLoader via the 'class' parameter, which is directly
    mapped to the getClass() method. A remote,
    unauthenticated attacker can take advantage of this
    issue to manipulate the ClassLoader used by the
    application server, allowing for the bypass of certain
    security restrictions. Note that CVE-2014-0112 exists
    because CVE-2014-0094 was not a complete fix.
    (CVE-2014-0094, CVE-2014-0112)");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2014/000257.html");
  # https://www.vmware.com/support/vcops/doc/vcops-582-vapp-release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d46f364");
  # https://www.vmware.com/support/vcops/doc/vcops-582-installable-release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1fe3ac72");
  # http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=2081470
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be20e92d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to vCenter Operations Manager 5.7.3 / 5.8.2 or later.

Alternatively, the vendor has provided a workaround for the security
bypass error.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts ClassLoader Manipulation Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_operations");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/VMware vCenter Operations Manager/Version");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/VMware vCenter Operations Manager/Version");
fix = NULL;

# 0.x - 4.x / 5.0.x - 5.6.x
#  - update with alt. version(s) when patch is available
if (version =~ "^([0-4]|5\.[0-6])($|[^0-9])")
  fix = "5.8.2";

# 5.7.x < 5.7.3
else if (version =~ "^5\.7\." && ver_compare(ver:version, fix:'5.7.3', strict:FALSE) < 0)
  fix = "5.7.3";

# 5.8.x < 5.8.2
else if (version =~ "^5\.8\." && ver_compare(ver:version, fix:'5.8.2', strict:FALSE) < 0)
  fix = "5.8.2";

if (!isnull(fix))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'VMware vCenter Operations Manager', version);
