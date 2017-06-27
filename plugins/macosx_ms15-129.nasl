#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87251);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/28 18:52:10 $");

  script_cve_id("CVE-2015-6114", "CVE-2015-6165", "CVE-2015-6166");
  script_osvdb_id(131331, 131332, 131333);
  script_xref(name:"MSFT", value:"MS15-129");

  script_name(english:"MS15-129: Security Update for Silverlight to Address Remote Code Execution (3106614) (Mac OS X)");
  script_summary(english:"Checks the version of Microsoft Silverlight.");

  script_set_attribute(attribute:"synopsis", value:
"A multimedia application framework installed on the remote Mac OS X
host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Silverlight installed on the remote Mac OS X
host is affected by the following vulnerabilities :

  - Multiple information disclosure vulnerabilities exist
    due to a failure to properly handle objects in memory.
    An attacker can exploit these issues, via crafted
    Silverlight content, to more reliably predict pointer
    values and thus degrade the effectiveness of the Address
    Space Layout Randomization (ASLR) security feature,
    allowing the system to be further compromised.
    (CVE-2015-6114, CVE-2015-6165)

  - A remote code execution vulnerability exists due to
    incorrect handling of certain open and close requests,
    which result in read and write access violations. A
    remote attacker can exploit this vulnerability, via a
    specially crafted Silverlight application, to gain
    privileges and take complete control of the affected
    host. (CVE-2015-6166)");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms15-129");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Silverlight 5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_silverlight_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Silverlight/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "MacOSX/Silverlight";
get_kb_item_or_exit(kb_base+"/Installed");
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);
version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);


bulletin = "MS15-129";
kb = "3106614";

fixed_version = "5.1.41105.0";
if (version =~ "^5\." && ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  if (defined_func("report_xml_tag")) report_xml_tag(tag:bulletin, value:kb);

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Microsoft Silverlight", version);
