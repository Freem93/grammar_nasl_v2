#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73225);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id("CVE-2013-7092", "CVE-2013-7103", "CVE-2013-7104");
  script_bugtraq_id(64150);
  script_osvdb_id(100581, 100582);
  script_xref(name:"MCAFEE-SB", value:"SB10064");

  script_name(english:"McAfee Email Gateway Multiple Vulnerabilities (SB10064)");
  script_summary(english:"Checks MEG version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple SQL injection and command
execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of McAfee Email Gateway (MEG)
that is affected by multiple SQL injection and command execution
vulnerabilities:

  - Multiple SQL injections vulnerabilities exist in the
    administrative web interface. A remote, authenticated
    attacker could potentially exploit these vulnerabilities
    to run arbitrary SQL commands. (CVE-2013-7092)

  - A command execution vulnerability exists in the
    administrative web interface due to a failure to
    sanitize user input to the 'TestFile' XML element. A
    remote, authenticated attacker could potentially exploit
    this vulnerability to run arbitrary shell commands.
    (CVE-2013-7103)

  - A command execution vulnerability exists in the
    administrative web interface due to a failure to
    sanitize user input to the 'Command' and 'Script' XML
    attribute. A remote, authenticated attacker could
    potentially exploit this vulnerability to run arbitrary
    shell commands. (CVE-2013-7104)");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10064");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/Dec/18");
  script_set_attribute(attribute:"solution", value:"Apply the relevant hotfix referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:email_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_dependencies("mcafee_email_gateway_version.nbin");
  script_require_keys("Host/McAfeeSMG/name", "Host/McAfeeSMG/version", "Host/McAfeeSMG/patches");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = get_kb_item_or_exit("Host/McAfeeSMG/name");
version = get_kb_item_or_exit("Host/McAfeeSMG/version");
patches = get_kb_item_or_exit("Host/McAfeeSMG/patches");

# Determine fix.
if (version =~ "^5\.6\.")
{
  fix = "5.6.2623.114";
  hotfix = "5.6h938402";
}
else if (version =~ "^7\.0\.")
{
  fix = "7.0.2795.110";
  hotfix = "7.0h938404";
}
else if (version =~ "^7\.5\.")
{
  fix = "7.5.2846.113";
  hotfix = "7.5h952384";
}
else if (version =~ "^7\.6\.")
{
  fix = "7.6.2810.112";
  hotfix = "7.6h938726";
}
else audit(AUDIT_INST_VER_NOT_VULN, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1 && hotfix >!< patches)
{
  port = 0;

  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report = '\n' + app_name + ' ' + version + ' is missing patch ' + hotfix + '.\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port:port);
  exit(0);
}
else audit(AUDIT_PATCH_INSTALLED, hotfix);
