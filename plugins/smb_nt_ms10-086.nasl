#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49963);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/04/23 21:35:40 $");

  script_cve_id("CVE-2010-3223");
  script_bugtraq_id(43818);
  script_osvdb_id(68554);
  script_xref(name:"IAVB", value:"2010-B-0089");
  script_xref(name:"MSFT", value:"MS10-086");

  script_name(english:"MS10-086: Vulnerability in Windows Shared Cluster Disks Could Allow Tampering (2294255)");
  script_summary(english:"Checks version of Clusres.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Windows host has a data tampering vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows 2008 R2 host has a data tampering vulnerability.
When the host is used as a shared failover cluster, the Failover
Cluster Manager uses insecure default permissions when adding disks to
a cluster.

This allows unauthorized read, write, and delete access to the
administrative shares on the failover cluster disk.

By default, Windows 2008 R2 servers are not affected.  This
vulnerability only applies to the cluster disks used in a failover
cluster."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-086");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Windows 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "wmi_enum_server_features.nbin", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-086';
kbs = make_list("2294255");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# 33  = Failover Clustering
if (!get_kb_item('WMI/server_feature/33'))
  exit(0, 'The Failover Clustering feature is not installed.');

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"6.1", file:"Clusres.dll", version:"6.1.7600.20777", min_version:"6.1.7600.20000", dir:"\Cluster", bulletin:bulletin, kb:"2294255") ||
  hotfix_is_vulnerable(os:"6.1", file:"Clusres.dll", version:"6.1.7600.16652", min_version:"6.1.7600.16000", dir:"\Cluster", bulletin:bulletin, kb:"2294255")
)
{
  set_kb_item(name:'SMB/Missing/MS10-086', value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
