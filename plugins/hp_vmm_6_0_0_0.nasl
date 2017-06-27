#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(46239);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/19 01:42:50 $");

  script_cve_id("CVE-2010-1035");
  script_bugtraq_id(39637);
  script_xref(name:"OSVDB", value:"64055");
  script_xref(name:"Secunia", value:"39583");

  script_name(english:"HP Virtual Machine Manager For Windows < 6.0.0.0");
  script_summary(english:"Checks the product version in the KB");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The virtualization manager on the remote Windows host has multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of HP Virtual Machine Manager running on the remote host
has multiple, unspecified vulnerabilities.  These include unauthorized
access and privilege escalation vulnerabilities. 

An authenticated attacker can reportedly exploit these issues to take
control of the host."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2010/Apr/201"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02031621
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ebbc0965"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to HP Virtual Machine Manager 6.0.0.0 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/04/21");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/04/21");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/05/05");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:insight_virtual_machine_management");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_vmm_installed.nasl");
  script_require_keys("SMB/hpvmm/version");

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");

ver = get_kb_item("SMB/hpvmm/version");
if (!ver) exit(1, "The 'SMB/hpvmm/version' KB item is missing.");

# Versions < 6.0.0.0 are vulnerable.
v = split(ver, sep:'.', keep:FALSE);
if (int(v[0]) < 6)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report =
      '\nInstalled version : '+ver+
      '\nFixed version     : 6.0.0.0\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, 'HP VMM version '+ver+' is not affected.');
