#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52013);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/03/12 14:23:03 $");

  script_cve_id("CVE-2010-2427", "CVE-2010-2667");
  script_bugtraq_id(41566, 41568);
  script_osvdb_id(66433, 66434);
  script_xref(name:"VMSA", value:"2010-0011");

  script_name(english:"VMware Studio 2.x < 2.1 Multiple Vulnerabilities");
  script_summary(english:"Looks for version of VMware Studio");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote VMware host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of VMware Studio installed on the remote host is 2.x prior
to 2.1.  It is, therefore, potentially affected by multiple
vulnerabilities :

  - An authenticated code execution vulnerability exists in
    the Virtual Appliance Management Infrastructure.
    (CVE-2010-2667)

  - A local privilege escalation vulnerability exists.
    (CVE-2010-2427)");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.vmware.com/security/advisories/VMSA-2010-0011.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2010/000101.html"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Studio 2.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:studio");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/VMware Studio/Version");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/VMware Studio/Version");

if (version =~ '^2\\.' && ver_compare(ver:version, fix:'2.1.0') < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.1.0\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'VMware Studio', version);
