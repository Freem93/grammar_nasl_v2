#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59821);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/09/06 13:39:47 $");

  script_cve_id(
    "CVE-2012-2495",
    "CVE-2012-2498",
    "CVE-2012-2499",
    "CVE-2012-2500"
  );
  script_bugtraq_id(54108, 54826, 54847);
  script_osvdb_id(83159, 84469, 84470, 84472);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtx74235");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtz26985");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtz29197");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtz29470");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120620-ac");

  script_name(english:"Cisco AnyConnect Secure Mobility Client 3.0 < 3.0 MR8 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Cisco AnyConnect Client");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has software installed that is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of Cisco AnyConnect < 3.0 MR8.
Such versions are affected by the following vulnerabilities :

  - The HostScan VPN downloader implementation does not 
    compare timestamps of offered software to install
    with currently installed software, which may allow
    remote attackers to downgrade the software via ActiveX
    or Java components. (CVE-2012-2495)

  - Man-in-the-middle attacks are possible even when the
    ASA is configured with a legitimate certificate.
    (CVE-2012-2498)

  - No certificate name checking is performed when using
    IPsec as the tunnel protocol, which could result in
    man-in-the-middle attacks. (CVE-2012-2499)

  - Certificate names are not verified during WebLaunch
    of IPsec, which could result in man-in-the-middle
    attacks. (CVE-2012-2500)"
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120620-ac
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?b0b6c065");
  # http://www.cisco.com/en/US/docs/security/vpn_client/anyconnect/anyconnect30/release/notes/anyconnect30rn.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?86b883fe");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Cisco AnyConnect Secure Mobility Client 3.0 MR8 or 
greater."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date",value:"2012/06/20");
  script_set_attribute(attribute:"patch_publication_date",value:"2012/06/20");
  script_set_attribute(attribute:"plugin_publication_date",value:"2012/07/02");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies('cisco_anyconnect_vpn_installed.nasl');
  script_require_keys('SMB/cisco_anyconnect/Installed');
  
  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('audit.inc');

appname = 'Cisco AnyConnect Mobility VPN Client';
kb_base = 'SMB/cisco_anyconnect/';
report = '';

num_installed = get_kb_item_or_exit(kb_base + 'NumInstalled');

for (install_num = 0; install_num < num_installed; install_num++)
{
  path = get_kb_item_or_exit(kb_base + install_num + '/path');
  ver = get_kb_item_or_exit(kb_base + install_num + '/version');
  fix = '3.0.8057.0';
  
  if (ver =~ "^3\." && ver_compare(ver:ver, fix:fix) == -1)
  {
      report += 
        '\n  Path              : ' + path +
        '\n  Installed version : ' + ver +
        '\n  Fixed version     : ' + fix + '\n';
  }
}

if(report != '')
{
  if (report_verbosity > 0)
    security_warning(port:get_kb_item('SMB/transport'), extra:report);
  else security_warning(get_kb_item('SMB/transport'));
  exit(0);
} 
else audit(AUDIT_INST_VER_NOT_VULN, appname);
